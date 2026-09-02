# Customer setup

1. Create a Supabase project and apply the SQL migrations in `supabase/migrations/`.
2. Copy `assets/js/supabase-config.example.js` to `assets/js/supabase-config.js` and enter the customer's own project URL and publishable key.
3. Run the ingestion API using the production integration guide. Keep the ingest key in a secret manager.
4. For Wazuh, follow `integrations/wazuh/README.md`.

The product archive intentionally does not include the seller's Supabase configuration, customer records, or local database file.
