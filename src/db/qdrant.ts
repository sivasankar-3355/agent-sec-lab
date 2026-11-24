import { QdrantClient } from "@qdrant/js-client-rest";

export class QdrantStore {
  private readonly client: QdrantClient;

  constructor(url: string) {
    this.client = new QdrantClient({
      url,
      timeout: 3000,
    });
  }

  async ping(): Promise<boolean> {
    try {
      await this.client.getCollections();
      return true;
    } catch {
      return false;
    }
  }

  getClient(): QdrantClient {
    return this.client;
  }
}
