import { MongoClient, type Db } from "mongodb";

export class MongoStore {
  private client: MongoClient;

  constructor(
    uri: string,
    private readonly databaseName: string,
  ) {
    this.client = new MongoClient(uri, {
      serverSelectionTimeoutMS: 3000,
      connectTimeoutMS: 3000,
    });
  }

  async connect(): Promise<void> {
    await this.client.connect();
  }

  async close(): Promise<void> {
    await this.client.close();
  }

  async ping(): Promise<boolean> {
    try {
      await this.client.db(this.databaseName).command({ ping: 1 });
      return true;
    } catch {
      return false;
    }
  }

  db(): Db {
    return this.client.db(this.databaseName);
  }
}
