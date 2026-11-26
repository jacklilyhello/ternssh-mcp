import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";

export function jobStorage(t) {
  const db = new DatabaseSync(":memory:");
  t.after(() => db.close());
  // Exercise production SQL. DO SQL uses ArrayBuffers for BLOB values.
  const storage = {
    sql: {
      exec(query, ...values) {
        const statement = db.prepare(query);
        const bindings = values.map((v) => v instanceof ArrayBuffer ? new Uint8Array(v) : v);
        let rows = [];
        if (/^SELECT/i.test(query)) {
          rows = statement.all(...bindings).map((row) => Object.fromEntries(
            Object.entries(row).map(([k, v]) => [k, v instanceof Uint8Array ? Uint8Array.from(v).buffer : v]),
          ));
        } else {
          statement.run(...bindings);
        }
        return {
          toArray: () => rows,
          one() {
            assert.equal(rows.length, 1);
            return rows[0];
          },
        };
      },
    },
    transactionSync(write) {
      db.exec("BEGIN");
      try {
        const result = write();
        db.exec("COMMIT");
        return result;
      } catch (error) {
        db.exec("ROLLBACK");
        throw error;
      }
    },
  };
  return storage;
}
