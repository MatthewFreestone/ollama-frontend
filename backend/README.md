Handles streaming request between Ollama and the user.
Handles auth and history

DB:

If you make a change, you can try to figure out migrations.

If you're lazy: 
1. modify the sql file
2. delete template.db
3. `cargo sqlx database create`
4. `cargo sqlx migrate run`
5. Then `cargo build`