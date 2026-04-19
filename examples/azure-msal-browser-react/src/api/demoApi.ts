export interface DemoItem {
    id: string;
    title: string;
    createdAt: string;
}

export interface DemoHealthResponse {
    status: string;
    itemCount: number;
}

export interface DemoItemsResponse {
    items: DemoItem[];
}

export interface DemoDeleteResponse {
    deletedId: string;
}

export interface DemoRequestResult {
    method: string;
    path: string;
    status: number;
    body: unknown;
}

export class DemoApiError extends Error {
    status: number;

    constructor(message: string, status: number) {
        super(message);
        this.name = "DemoApiError";
        this.status = status;
    }
}

async function request<T>(path: string, init?: RequestInit): Promise<{ data: T; result: DemoRequestResult }> {
    const method = init?.method ?? "GET";
    const response = await fetch(`/api${path}`, {
        ...init,
        headers: {
            "Content-Type": "application/json",
            ...(init?.headers ?? {}),
        },
    });

    const rawText = await response.text();
    const body = rawText ? JSON.parse(rawText) as unknown : null;

    if (!response.ok) {
        const message = typeof body === "object" && body !== null && "error" in body && typeof body.error === "string"
            ? body.error
            : `${method} ${path} failed`;
        throw new DemoApiError(message, response.status);
    }

    return {
        data: body as T,
        result: {
            method,
            path: `/api${path}`,
            status: response.status,
            body,
        },
    };
}

export async function getHealth() {
    return request<DemoHealthResponse>("/health");
}

export async function getItems() {
    return request<DemoItemsResponse>("/items");
}

export async function createItem(title: string) {
    return request<DemoItem>("/items", {
        method: "POST",
        body: JSON.stringify({ title }),
    });
}

export async function deleteItem(id: string) {
    return request<DemoDeleteResponse>(`/items/${id}`, {
        method: "DELETE",
    });
}
