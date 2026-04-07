// SPDX-License-Identifier: Apache-2.0

package weaverprocessor

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"github.com/tetratelabs/wazero"
	wazeroapi "github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.uber.org/zap"
)

// weaverProcessor validates telemetry via a Weaver WASM module and passes
// it through unchanged. Validation findings are logged.
type weaverProcessor struct {
	logger      *zap.Logger
	cfg         *Config
	nextMetrics consumer.Metrics
	nextTraces  consumer.Traces
	nextLogs    consumer.Logs

	mu      sync.Mutex
	runtime wazero.Runtime
	mod     wazero.CompiledModule
	inst    api
}

type wasmFunc = func(ctx context.Context, args ...uint64) ([]uint64, error)

// api wraps the exported WASM functions for convenience.
type api struct {
	alloc      wasmFunc
	dealloc    wasmFunc
	init       wasmFunc
	check      wasmFunc
	freeResult wasmFunc
	mod        wazeroapi.Module
}

func newWeaverProcessor(
	logger *zap.Logger,
	cfg *Config,
	nextMetrics consumer.Metrics,
	nextTraces consumer.Traces,
	nextLogs consumer.Logs,
) (*weaverProcessor, error) {
	return &weaverProcessor{
		logger:      logger,
		cfg:         cfg,
		nextMetrics: nextMetrics,
		nextTraces:  nextTraces,
		nextLogs:    nextLogs,
	}, nil
}

// Start loads the WASM module and initialises the Rego engine.
func (p *weaverProcessor) Start(ctx context.Context, _ component.Host) error {
	p.logger.Info("Starting Weaver processor", zap.String("wasm_path", p.cfg.WASMPath))

	wasmBytes, err := os.ReadFile(p.cfg.WASMPath)
	if err != nil {
		return fmt.Errorf("reading wasm module: %w", err)
	}

	r := wazero.NewRuntime(ctx)
	wasi_snapshot_preview1.MustInstantiate(ctx, r)

	compiled, err := r.CompileModule(ctx, wasmBytes)
	if err != nil {
		_ = r.Close(ctx)
		return fmt.Errorf("compiling wasm module: %w", err)
	}

	inst, err := r.InstantiateModule(ctx, compiled, wazero.NewModuleConfig().
		WithStdout(os.Stdout).WithStderr(os.Stderr))
	if err != nil {
		_ = r.Close(ctx)
		return fmt.Errorf("instantiating wasm module: %w", err)
	}

	p.runtime = r
	p.mod = compiled
	p.inst = api{
		alloc:      inst.ExportedFunction("alloc").Call,
		dealloc:    inst.ExportedFunction("dealloc").Call,
		init:       inst.ExportedFunction("init").Call,
		check:      inst.ExportedFunction("check").Call,
		freeResult: inst.ExportedFunction("free_result").Call,
		mod:        inst,
	}

	// Initialise with policies (if provided).
	policies := "[]"
	if p.cfg.PoliciesJSON != "" {
		policies = p.cfg.PoliciesJSON
	}
	if err := p.callInit(ctx, []byte(policies)); err != nil {
		return fmt.Errorf("initialising wasm policies: %w", err)
	}

	p.logger.Info("Weaver processor started")
	return nil
}

// Shutdown releases the WASM runtime.
func (p *weaverProcessor) Shutdown(ctx context.Context) error {
	if p.runtime != nil {
		return p.runtime.Close(ctx)
	}
	return nil
}

// Capabilities reports that the processor does not mutate data.
func (p *weaverProcessor) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{MutatesData: false}
}

// --- Signal processing (pass-through + validation) ---

func (p *weaverProcessor) ConsumeMetrics(ctx context.Context, md pmetric.Metrics) error {
	p.validateMetrics(ctx, md)
	if p.nextMetrics != nil {
		return p.nextMetrics.ConsumeMetrics(ctx, md)
	}
	return nil
}

func (p *weaverProcessor) ConsumeTraces(ctx context.Context, td ptrace.Traces) error {
	p.validateTraces(ctx, td)
	if p.nextTraces != nil {
		return p.nextTraces.ConsumeTraces(ctx, td)
	}
	return nil
}

func (p *weaverProcessor) ConsumeLogs(ctx context.Context, ld plog.Logs) error {
	if p.nextLogs != nil {
		return p.nextLogs.ConsumeLogs(ctx, ld)
	}
	return nil
}

// --- Validation helpers ---

func (p *weaverProcessor) validateMetrics(ctx context.Context, md pmetric.Metrics) {
	marshaler := pmetric.JSONMarshaler{}
	jsonBytes, err := marshaler.MarshalMetrics(md)
	if err != nil {
		p.logger.Error("Failed to marshal metrics to JSON", zap.Error(err))
		return
	}
	p.runCheck(ctx, jsonBytes, 3) // LiveCheckAdvice stage
}

func (p *weaverProcessor) validateTraces(ctx context.Context, td ptrace.Traces) {
	marshaler := ptrace.JSONMarshaler{}
	jsonBytes, err := marshaler.MarshalTraces(td)
	if err != nil {
		p.logger.Error("Failed to marshal traces to JSON", zap.Error(err))
		return
	}
	p.runCheck(ctx, jsonBytes, 3) // LiveCheckAdvice stage
}

func (p *weaverProcessor) runCheck(ctx context.Context, input []byte, stage int) {
	p.mu.Lock()
	defer p.mu.Unlock()

	findings, err := p.callCheck(ctx, input, stage)
	if err != nil {
		p.logger.Error("WASM check failed", zap.Error(err))
		return
	}

	if len(findings) == 0 {
		return
	}

	for _, f := range findings {
		level := zap.InfoLevel
		switch f.Level {
		case "violation":
			level = zap.ErrorLevel
		case "improvement":
			level = zap.WarnLevel
		}
		p.logger.Log(level, f.Message,
			zap.String("finding_id", f.ID),
			zap.String("finding_level", f.Level),
			zap.String("signal_type", f.SignalType),
			zap.String("signal_name", f.SignalName),
		)
	}
}

// --- WASM call helpers ---

// Finding represents a policy finding returned by the WASM module.
type Finding struct {
	ID         string          `json:"id"`
	Level      string          `json:"level"`
	Message    string          `json:"message"`
	Context    json.RawMessage `json:"context,omitempty"`
	SignalType string          `json:"signal_type,omitempty"`
	SignalName string          `json:"signal_name,omitempty"`
}

func (p *weaverProcessor) callInit(ctx context.Context, policiesJSON []byte) error {
	ptr, err := p.writeToWasm(ctx, policiesJSON)
	if err != nil {
		return err
	}
	defer func() { _, _ = p.inst.dealloc(ctx, ptr, uint64(len(policiesJSON))) }()

	results, err := p.inst.init(ctx, ptr, uint64(len(policiesJSON)))
	if err != nil {
		return fmt.Errorf("wasm init call: %w", err)
	}
	if status := results[0]; status != 0 {
		return fmt.Errorf("wasm init returned status %d", status)
	}
	return nil
}

func (p *weaverProcessor) callCheck(ctx context.Context, input []byte, stage int) ([]Finding, error) {
	ptr, err := p.writeToWasm(ctx, input)
	if err != nil {
		return nil, err
	}
	defer func() { _, _ = p.inst.dealloc(ctx, ptr, uint64(len(input))) }()

	// Allocate space for output pointer and length (8 bytes each in wasm32).
	outPtrPtr, err := p.allocWasm(ctx, 8)
	if err != nil {
		return nil, err
	}
	defer func() { _, _ = p.inst.dealloc(ctx, outPtrPtr, 8) }()
	outLenPtr, err := p.allocWasm(ctx, 4)
	if err != nil {
		return nil, err
	}
	defer func() { _, _ = p.inst.dealloc(ctx, outLenPtr, 4) }()

	results, err := p.inst.check(ctx, ptr, uint64(len(input)), uint64(stage), outPtrPtr, outLenPtr)
	if err != nil {
		return nil, fmt.Errorf("wasm check call: %w", err)
	}
	if status := results[0]; status != 0 {
		return nil, fmt.Errorf("wasm check returned status %d", status)
	}

	// Read the output pointer and length from WASM memory.
	mem := p.inst.mod.Memory()
	resultPtr, ok := mem.ReadUint32Le(uint32(outPtrPtr))
	if !ok {
		return nil, fmt.Errorf("failed to read result pointer")
	}
	resultLen, ok := mem.ReadUint32Le(uint32(outLenPtr))
	if !ok {
		return nil, fmt.Errorf("failed to read result length")
	}

	resultBytes, ok := mem.Read(resultPtr, resultLen)
	if !ok {
		return nil, fmt.Errorf("failed to read result bytes")
	}

	// Free the WASM-side result buffer.
	_, _ = p.inst.freeResult(ctx, uint64(resultPtr), uint64(resultLen))

	var findings []Finding
	if err := json.Unmarshal(resultBytes, &findings); err != nil {
		return nil, fmt.Errorf("unmarshal findings: %w", err)
	}
	return findings, nil
}

func (p *weaverProcessor) writeToWasm(ctx context.Context, data []byte) (uint64, error) {
	ptr, err := p.allocWasm(ctx, uint32(len(data)))
	if err != nil {
		return 0, err
	}
	mem := p.inst.mod.Memory()
	if !mem.Write(uint32(ptr), data) {
		return 0, fmt.Errorf("failed to write %d bytes to wasm memory", len(data))
	}
	return ptr, nil
}

func (p *weaverProcessor) allocWasm(ctx context.Context, size uint32) (uint64, error) {
	results, err := p.inst.alloc(ctx, uint64(size))
	if err != nil {
		return 0, fmt.Errorf("wasm alloc(%d): %w", size, err)
	}
	return results[0], nil
}
