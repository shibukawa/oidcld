import { useEffect, useState } from "react";
import { createItem, deleteItem, getHealth, getItems, type DemoHealthResponse, type DemoItem, type DemoRequestResult } from "../api/demoApi";

function formatTimestamp(value: string): string {
    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) {
        return value;
    }
    return parsed.toLocaleString();
}

export const ApiDemoPanel = () => {
    const [items, setItems] = useState<DemoItem[]>([]);
    const [health, setHealth] = useState<DemoHealthResponse | null>(null);
    const [requestSummary, setRequestSummary] = useState<DemoRequestResult | null>(null);
    const [draftTitle, setDraftTitle] = useState("");
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [initialized, setInitialized] = useState(false);

    const loadState = async () => {
        setLoading(true);
        setError(null);
        try {
            const [healthResponse, itemsResponse] = await Promise.all([getHealth(), getItems()]);
            setHealth(healthResponse.data);
            setItems(itemsResponse.data.items);
            setRequestSummary(itemsResponse.result);
        } catch (err) {
            setError(err instanceof Error ? err.message : "Failed to load demo API data");
        } finally {
            setLoading(false);
            setInitialized(true);
        }
    };

    useEffect(() => {
        if (initialized) {
            return;
        }
        void loadState();
    }, [initialized]);

    const handleCreate = async (event: React.FormEvent<HTMLFormElement>) => {
        event.preventDefault();
        const title = draftTitle.trim();
        if (!title) {
            setError("Title is required");
            return;
        }

        setLoading(true);
        setError(null);
        try {
            const created = await createItem(title);
            const refreshed = await getHealth();
            setItems((current) => [created.data, ...current]);
            setHealth(refreshed.data);
            setRequestSummary(created.result);
            setDraftTitle("");
        } catch (err) {
            setError(err instanceof Error ? err.message : "Failed to create item");
        } finally {
            setLoading(false);
        }
    };

    const handleDelete = async (id: string) => {
        setLoading(true);
        setError(null);
        try {
            const deleted = await deleteItem(id);
            const refreshed = await getHealth();
            setItems((current) => current.filter((item) => item.id !== id));
            setHealth(refreshed.data);
            setRequestSummary(deleted.result);
        } catch (err) {
            setError(err instanceof Error ? err.message : "Failed to delete item");
        } finally {
            setLoading(false);
        }
    };

    const handleRefresh = async () => {
        await loadState();
    };

    return (
        <div className="bg-white rounded-lg shadow-sm p-6 space-y-6">
            <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
                <div>
                    <h3 className="text-2xl font-bold text-blue-600">API Access Demo</h3>
                    <p className="text-gray-700 mt-2">
                        This panel calls the reverse-proxied demo service mounted at <code>/api</code>.
                    </p>
                </div>
                <button
                    className="bg-slate-800 hover:bg-slate-900 text-white font-medium py-2 px-4 rounded-md transition-colors duration-200 disabled:opacity-50"
                    disabled={loading}
                    onClick={() => {
                        void handleRefresh();
                    }}
                    type="button"
                >
                    {loading ? "Loading..." : "Refresh GET /api/items"}
                </button>
            </div>

            <div className="grid gap-4 md:grid-cols-3">
                <div className="bg-blue-50 border border-blue-100 rounded-lg p-4">
                    <p className="text-sm font-medium text-blue-700">Service status</p>
                    <p className="text-2xl font-bold text-slate-900 mt-2">{health?.status ?? "..."}</p>
                </div>
                <div className="bg-emerald-50 border border-emerald-100 rounded-lg p-4">
                    <p className="text-sm font-medium text-emerald-700">Stored items</p>
                    <p className="text-2xl font-bold text-slate-900 mt-2">{health?.itemCount ?? items.length}</p>
                </div>
                <div className="bg-amber-50 border border-amber-100 rounded-lg p-4">
                    <p className="text-sm font-medium text-amber-700">Last request</p>
                    <p className="text-sm font-semibold text-slate-900 mt-2">
                        {requestSummary ? `${requestSummary.method} ${requestSummary.path}` : "No request yet"}
                    </p>
                    <p className="text-xs text-slate-600 mt-1">
                        {requestSummary ? `HTTP ${requestSummary.status}` : "Run a request to inspect the response"}
                    </p>
                </div>
            </div>

            <form className="bg-gray-50 rounded-lg p-4 border border-gray-200 space-y-3" onSubmit={handleCreate}>
                <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2" htmlFor="demo-item-title">
                        POST /api/items
                    </label>
                    <div className="flex flex-col gap-3 md:flex-row">
                        <input
                            className="flex-1 rounded-md border border-gray-300 px-3 py-2 text-gray-900 shadow-sm focus:border-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-500"
                            id="demo-item-title"
                            onChange={(event) => {
                                setDraftTitle(event.target.value);
                            }}
                            placeholder="Add an item title"
                            value={draftTitle}
                        />
                        <button
                            className="bg-blue-600 hover:bg-blue-700 text-white font-medium py-2 px-4 rounded-md transition-colors duration-200 disabled:opacity-50"
                            disabled={loading}
                            type="submit"
                        >
                            Create Item
                        </button>
                    </div>
                </div>
            </form>

            {error && (
                <div className="bg-red-50 border border-red-200 rounded-md p-4">
                    <p className="text-red-800 font-medium">Error: {error}</p>
                </div>
            )}

            <div className="grid gap-6 lg:grid-cols-[1.4fr_1fr]">
                <div className="space-y-3">
                    <h4 className="text-lg font-semibold text-gray-900">Current Items</h4>
                    {items.length === 0 ? (
                        <div className="bg-gray-50 border border-dashed border-gray-300 rounded-lg p-6 text-gray-600">
                            No items yet. Create one to generate GET/POST/DELETE traffic for the reverse proxy logs.
                        </div>
                    ) : (
                        <div className="space-y-3">
                            {items.map((item) => (
                                <div key={item.id} className="bg-gray-50 rounded-lg border border-gray-200 p-4 flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
                                    <div>
                                        <p className="font-semibold text-slate-900">{item.title}</p>
                                        <p className="text-xs text-slate-500 mt-1">ID: {item.id}</p>
                                        <p className="text-xs text-slate-500">Created: {formatTimestamp(item.createdAt)}</p>
                                    </div>
                                    <button
                                        className="bg-red-600 hover:bg-red-700 text-white font-medium py-2 px-4 rounded-md transition-colors duration-200 disabled:opacity-50"
                                        disabled={loading}
                                        onClick={() => {
                                            void handleDelete(item.id);
                                        }}
                                        type="button"
                                    >
                                        DELETE /api/items/{item.id}
                                    </button>
                                </div>
                            ))}
                        </div>
                    )}
                </div>

                <div className="space-y-3">
                    <h4 className="text-lg font-semibold text-gray-900">Last Response Body</h4>
                    <div className="bg-slate-950 text-slate-100 rounded-lg p-4 overflow-auto min-h-64">
                        <pre className="text-xs whitespace-pre-wrap break-all">
                            {JSON.stringify(requestSummary?.body ?? { message: "No response captured yet" }, null, 2)}
                        </pre>
                    </div>
                </div>
            </div>
        </div>
    );
};
