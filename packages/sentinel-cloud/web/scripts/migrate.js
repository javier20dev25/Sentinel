import pkg from 'pg';
const { Client } = pkg;
import fs from 'fs';
import path from 'path';
import 'dotenv/config';

const connectionString = process.env.DIRECT_URL || process.env.DATABASE_URL;

if (!connectionString) {
  console.error("No DATABASE_URL or DIRECT_URL found in .env.local");
  process.exit(1);
}

const client = new Client({
  connectionString: connectionString,
  ssl: {
    rejectUnauthorized: false
  }
});

async function migrate(): Promise<void> {
  try {
    await client.connect();
    console.log("Connected to Supabase PostgreSQL");

    const schemaPath = path.join(process.cwd(), 'supabase', 'schema.sql');
    if (!fs.existsSync(schemaPath)) {
      console.error("Schema file not found at", schemaPath);
      process.exit(1);
    }

    const sql = fs.readFileSync(schemaPath, 'utf8');
    console.log("Executing schema.sql...");
    
    // Split into individual statements to avoid some PG issues
    const statements = sql.split(';').filter(s => s.trim().length > 0);
    
    for (const statement of statements) {
      try {
        await client.query(statement);
      } catch (err: unknown) {
        const error = err as { message: string };
        if (error.message.includes('already exists')) {
          console.log(`Skipping: ${error.message.split('\n')[0]}`);
        } else {
          throw err;
        }
      }
    }

    console.log("Migration completed successfully!");
  } catch (error: unknown) {
    console.error("Migration failed:", error);
  } finally {
    await client.end();
  }
}

migrate().catch(console.error);
