-- =============================================================================
-- Migration 029: Finding Data Flows (SARIF codeFlows)
-- OpenCTEM OSS Edition
-- =============================================================================
-- Purpose: Enable queryable taint tracking paths from source to sink
-- Use case: Attack path analysis, data flow queries across files/functions

-- Finding Data Flows: Container for code flow paths
-- Maps to SARIF codeFlows array - each finding can have multiple data flow traces
CREATE TABLE IF NOT EXISTS finding_data_flows (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    flow_index INTEGER NOT NULL DEFAULT 0,
    message TEXT,
    importance VARCHAR(20) DEFAULT 'essential',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_flow_importance CHECK (importance IN ('essential', 'important', 'unimportant')),
    CONSTRAINT uq_finding_data_flow UNIQUE (finding_id, flow_index)
);

COMMENT ON TABLE finding_data_flows IS 'SARIF codeFlows - taint tracking paths from source to sink';
COMMENT ON COLUMN finding_data_flows.flow_index IS 'Order of this flow within the finding (0-based)';
COMMENT ON COLUMN finding_data_flows.importance IS 'SARIF threadFlowImportance: essential, important, unimportant';

-- Finding Flow Locations: Individual steps in a data flow
-- Maps to SARIF threadFlowLocation - each step in the taint path
CREATE TABLE IF NOT EXISTS finding_flow_locations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    data_flow_id UUID NOT NULL REFERENCES finding_data_flows(id) ON DELETE CASCADE,
    step_index INTEGER NOT NULL,
    location_type VARCHAR(20) NOT NULL DEFAULT 'intermediate',

    -- Physical location (file/line/column)
    file_path VARCHAR(1000),
    start_line INTEGER,
    end_line INTEGER,
    start_column INTEGER,
    end_column INTEGER,
    snippet TEXT,

    -- Logical location (function/class/module context)
    function_name VARCHAR(500),
    class_name VARCHAR(500),
    fully_qualified_name VARCHAR(1000),
    module_name VARCHAR(500),

    -- Context
    label VARCHAR(500),
    message TEXT,
    nesting_level INTEGER DEFAULT 0,

    -- Step importance (SARIF importance enum)
    importance VARCHAR(20) DEFAULT 'essential',

    CONSTRAINT chk_flow_location_type CHECK (location_type IN ('source', 'intermediate', 'sink', 'sanitizer')),
    CONSTRAINT chk_location_importance CHECK (importance IN ('essential', 'important', 'unimportant'))
);

COMMENT ON TABLE finding_flow_locations IS 'Individual steps in a data flow trace (source -> intermediate -> sink)';
COMMENT ON COLUMN finding_flow_locations.location_type IS 'Role in flow: source (taint origin), intermediate (propagation), sink (vulnerable use), sanitizer (safe path)';
COMMENT ON COLUMN finding_flow_locations.label IS 'Variable/expression name being tracked through the flow';
COMMENT ON COLUMN finding_flow_locations.nesting_level IS 'SARIF nestingLevel for display indentation';

-- =============================================================================
-- Indexes
-- =============================================================================

-- Finding to flows relationship
CREATE INDEX IF NOT EXISTS idx_data_flows_finding ON finding_data_flows(finding_id);

-- Flow steps ordering
CREATE INDEX IF NOT EXISTS idx_flow_locations_flow_step ON finding_flow_locations(data_flow_id, step_index);

-- File-based queries ("find all flows through this file")
CREATE INDEX IF NOT EXISTS idx_flow_locations_file ON finding_flow_locations(file_path)
    WHERE file_path IS NOT NULL;

-- Function-based queries ("find all flows through this function")
CREATE INDEX IF NOT EXISTS idx_flow_locations_function ON finding_flow_locations(function_name)
    WHERE function_name IS NOT NULL;

-- Class-based queries
CREATE INDEX IF NOT EXISTS idx_flow_locations_class ON finding_flow_locations(class_name)
    WHERE class_name IS NOT NULL;

-- Location type queries ("find all sources/sinks")
CREATE INDEX IF NOT EXISTS idx_flow_locations_type ON finding_flow_locations(location_type);

-- Composite index for common query pattern
CREATE INDEX IF NOT EXISTS idx_flow_locations_file_line ON finding_flow_locations(file_path, start_line)
    WHERE file_path IS NOT NULL;

