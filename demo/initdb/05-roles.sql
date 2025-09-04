-- Demo roles and privileges for JWT role mapping
-- Roles: anon (least), reader (more), power (all demo)

-- Create roles if not exists
DO $$
BEGIN
   IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
      CREATE ROLE anon NOINHERIT;
   END IF;
   IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'reader') THEN
      CREATE ROLE reader NOINHERIT;
   END IF;
   IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'power') THEN
      CREATE ROLE power NOINHERIT;
   END IF;
END$$;

-- Allow basic usage of public schema
GRANT USAGE ON SCHEMA public TO anon, reader, power;
GRANT USAGE ON SCHEMA postgisftw TO anon, reader, power;

-- Ensure default privileges on future objects under public
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO reader, power;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON SEQUENCES TO reader, power;

-- Table/view privileges
-- anon: only cities_view
GRANT SELECT ON TABLE public.cities_view TO anon;

-- reader: cities and cities_view
GRANT SELECT ON TABLE public.cities TO reader;
GRANT SELECT ON TABLE public.cities_view TO reader;

-- power: everything in demo schemas
GRANT SELECT ON ALL TABLES IN SCHEMA public, postgisftw TO power;

GRANT USAGE ON SCHEMA postgisftw TO anon, reader, power;

-- IMPORTANT: by default, PUBLIC has EXECUTE on functions. Revoke broadly, then grant back
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA postgisftw FROM PUBLIC;

-- Future functions should not be executable by PUBLIC
ALTER DEFAULT PRIVILEGES IN SCHEMA postgisftw REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA postgisftw GRANT EXECUTE ON FUNCTIONS TO reader, power;

-- Grant function execution per role
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA postgisftw TO reader, power;
-- anon can only call the simplest function
GRANT EXECUTE ON FUNCTION postgisftw.buffer(geometry, numeric) TO anon;
