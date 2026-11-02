-- Recreates the empty catalog table (its rows were a downloaded copy and are
-- not restored).
CREATE TABLE IF NOT EXISTS public.ctem_id_catalog (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    ctem_id text NOT NULL,
    category text NOT NULL,
    title text NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    severity text DEFAULT ''::text NOT NULL,
    source_url text DEFAULT ''::text NOT NULL,
    published_at timestamp with time zone,
    raw jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ctem_id_catalog_pkey PRIMARY KEY (id),
    CONSTRAINT ctem_id_catalog_ctem_id_key UNIQUE (ctem_id)
);
