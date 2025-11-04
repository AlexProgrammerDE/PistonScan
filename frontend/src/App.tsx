import {ChangeEvent, useCallback, useEffect, useMemo, useState} from 'react';
import './App.css';
import {
    CancelScan,
    ExportResults,
    GetSnapshot,
    ImportResults,
    PauseScan,
    ResumeScan,
    StartScan
} from '../wailsjs/go/main/App';
import {EventsOn} from '../wailsjs/runtime/runtime';

interface ScanConfig {
    subnet: string;
    threadLimit: number;
    delayMs: number;
}

interface ScanProgress {
    total: number;
    completed: number;
    active: number;
    status: string;
}

interface ScanResult {
    ip: string;
    reachable: boolean;
    latencyMs: number;
    error?: string;
}

interface ScanSnapshot {
    config?: ScanConfig;
    progress: ScanProgress;
    results: ScanResult[];
    updated?: string;
}

interface ScanUpdate {
    result: ScanResult;
    progress: ScanProgress;
}

interface FormState {
    subnet: string;
    threadLimit: string;
    delayMs: string;
}

const defaultProgress: ScanProgress = {total: 0, completed: 0, active: 0, status: 'idle'};

const normaliseError = (error: unknown): string => {
    if (typeof error === 'string') {
        return error;
    }
    if (error && typeof error === 'object' && 'message' in error) {
        const message = (error as { message?: unknown }).message;
        if (typeof message === 'string') {
            return message;
        }
    }
    try {
        return JSON.stringify(error);
    } catch (_err) {
        return 'An unexpected error occurred.';
    }
};

function App() {
    const [form, setForm] = useState<FormState>({subnet: '', threadLimit: '4', delayMs: '0'});
    const [progress, setProgress] = useState<ScanProgress>(defaultProgress);
    const [results, setResults] = useState<ScanResult[]>([]);
    const [error, setError] = useState<string | null>(null);
    const [busyAction, setBusyAction] = useState<string | null>(null);

    const isRunning = progress.status === 'running';
    const isPaused = progress.status === 'paused';
    const hasResults = results.length > 0;

    const percentComplete = useMemo(() => {
        if (!progress.total) {
            return 0;
        }
        return Math.min(100, Math.round((progress.completed / progress.total) * 100));
    }, [progress.completed, progress.total]);

    const updateFormFromSnapshot = useCallback((snapshot: ScanSnapshot) => {
        if (snapshot.config) {
            setForm({
                subnet: snapshot.config.subnet ?? '',
                threadLimit: String(snapshot.config.threadLimit ?? 1),
                delayMs: String(snapshot.config.delayMs ?? 0)
            });
        }
    }, []);

    const loadSnapshot = useCallback(async () => {
        try {
            const snapshot = await GetSnapshot();
            setProgress(snapshot.progress ?? defaultProgress);
            setResults(snapshot.results ?? []);
            updateFormFromSnapshot(snapshot);
        } catch (err) {
            setError(normaliseError(err));
        }
    }, [updateFormFromSnapshot]);

    useEffect(() => {
        loadSnapshot().catch((err) => setError(normaliseError(err)));
    }, [loadSnapshot]);

    useEffect(() => {
        const offUpdate = EventsOn('scan:update', (data: ScanUpdate) => {
            if (!data || !data.result) {
                return;
            }
            setProgress(data.progress ?? defaultProgress);
            setResults((prev) => {
                const existingIndex = prev.findIndex((item) => item.ip === data.result.ip);
                if (existingIndex >= 0) {
                    const next = [...prev];
                    next[existingIndex] = data.result;
                    return next;
                }
                return [...prev, data.result];
            });
        });

        const offStatus = EventsOn('scan:status', (payload: ScanProgress) => {
            if (!payload) {
                return;
            }
            setProgress(payload);
        });

        return () => {
            offUpdate();
            offStatus();
        };
    }, []);

    const withBusy = async (action: string, fn: () => Promise<void>) => {
        setBusyAction(action);
        try {
            await fn();
        } finally {
            setBusyAction(null);
        }
    };

    const handleStart = async () => {
        setError(null);
        const subnet = form.subnet.trim();
        const threadLimit = Number.parseInt(form.threadLimit, 10);
        const delayMs = Number.parseInt(form.delayMs, 10);
        if (!subnet) {
            setError('Please provide a subnet or IP address to scan.');
            return;
        }
        if (!Number.isFinite(threadLimit) || threadLimit <= 0) {
            setError('Thread limit must be a positive number.');
            return;
        }
        if (!Number.isFinite(delayMs) || delayMs < 0) {
            setError('Delay must be zero or a positive number.');
            return;
        }

        await withBusy('start', async () => {
            try {
                const snapshot = await StartScan({subnet, threadLimit, delayMs});
                setProgress(snapshot.progress ?? defaultProgress);
                setResults(snapshot.results ?? []);
                updateFormFromSnapshot(snapshot);
            } catch (err) {
                setError(normaliseError(err));
            }
        });
    };

    const handlePause = async () => {
        await withBusy('pause', async () => {
            try {
                const payload = await PauseScan();
                setProgress(payload ?? defaultProgress);
            } catch (err) {
                setError(normaliseError(err));
            }
        });
    };

    const handleResume = async () => {
        await withBusy('resume', async () => {
            try {
                const payload = await ResumeScan();
                setProgress(payload ?? defaultProgress);
            } catch (err) {
                setError(normaliseError(err));
            }
        });
    };

    const handleCancel = async () => {
        await withBusy('cancel', async () => {
            try {
                const payload = await CancelScan();
                setProgress(payload ?? defaultProgress);
            } catch (err) {
                setError(normaliseError(err));
            }
        });
    };

    const handleExport = async () => {
        await withBusy('export', async () => {
            try {
                const data = await ExportResults();
                const blob = new Blob([data], {type: 'application/json'});
                const url = URL.createObjectURL(blob);
                const link = document.createElement('a');
                link.href = url;
                link.download = `pistonscan-${new Date().toISOString().replace(/[:.]/g, '-')}.json`;
                document.body.appendChild(link);
                link.click();
                document.body.removeChild(link);
                URL.revokeObjectURL(url);
            } catch (err) {
                setError(normaliseError(err));
            }
        });
    };

    const handleImport = async (event: ChangeEvent<HTMLInputElement>) => {
        const file = event.target.files?.[0];
        if (!file) {
            return;
        }
        event.target.value = '';
        await withBusy('import', async () => {
            try {
                const contents = await file.text();
                const snapshot = await ImportResults(contents);
                setResults(snapshot.results ?? []);
                setProgress(snapshot.progress ?? defaultProgress);
                updateFormFromSnapshot(snapshot);
            } catch (err) {
                setError(normaliseError(err));
            }
        });
    };

    const updateFormValue = (field: keyof FormState) => (event: ChangeEvent<HTMLInputElement>) => {
        setForm((prev) => ({...prev, [field]: event.target.value}));
    };

    const statusLabel = useMemo(() => {
        switch (progress.status) {
            case 'running':
                return 'Running';
            case 'paused':
                return 'Paused';
            case 'cancelled':
                return 'Cancelled';
            case 'completed':
                return 'Completed';
            default:
                return 'Idle';
        }
    }, [progress.status]);

    return (
        <div id="App">
            <header className="app-header">
                <h1>PistonScan</h1>
                <p className="tagline">Discover responsive hosts in your network with live updates.</p>
            </header>

            <section className="scan-form">
                <div className="form-group">
                    <label htmlFor="subnet">Subnet / IP</label>
                    <input
                        id="subnet"
                        type="text"
                        value={form.subnet}
                        onChange={updateFormValue('subnet')}
                        placeholder="e.g. 192.168.1.0/24"
                    />
                </div>
                <div className="form-group">
                    <label htmlFor="threads">Threads</label>
                    <input
                        id="threads"
                        type="number"
                        min={1}
                        value={form.threadLimit}
                        onChange={updateFormValue('threadLimit')}
                    />
                </div>
                <div className="form-group">
                    <label htmlFor="delay">Delay (ms)</label>
                    <input
                        id="delay"
                        type="number"
                        min={0}
                        value={form.delayMs}
                        onChange={updateFormValue('delayMs')}
                    />
                </div>
                <div className="control-buttons">
                    <button onClick={handleStart} disabled={isRunning || isPaused || busyAction === 'start'}>
                        Start Scan
                    </button>
                    <button onClick={handlePause} disabled={!isRunning || busyAction === 'pause'}>
                        Pause
                    </button>
                    <button onClick={handleResume} disabled={!isPaused || busyAction === 'resume'}>
                        Resume
                    </button>
                    <button onClick={handleCancel} disabled={(!isRunning && !isPaused) || busyAction === 'cancel'}>
                        Cancel
                    </button>
                </div>
            </section>

            <section className="scan-summary">
                <div className="summary-item">
                    <span className="summary-label">Status</span>
                    <span className={`summary-value status-${progress.status}`}>{statusLabel}</span>
                </div>
                <div className="summary-item">
                    <span className="summary-label">Completed</span>
                    <span className="summary-value">{progress.completed} / {progress.total}</span>
                </div>
                <div className="summary-item">
                    <span className="summary-label">Active Threads</span>
                    <span className="summary-value">{progress.active}</span>
                </div>
                <div className="summary-item">
                    <span className="summary-label">Progress</span>
                    <span className="summary-value">{percentComplete}%</span>
                </div>
                <div className="summary-actions">
                    <button onClick={handleExport} disabled={!hasResults || busyAction === 'export'}>
                        Export
                    </button>
                    <label className={busyAction === 'import' ? 'import-label busy' : 'import-label'}>
                        Import
                        <input type="file" accept="application/json" onChange={handleImport} disabled={busyAction === 'import'} />
                    </label>
                </div>
            </section>

            {error && <div className="error-banner">{error}</div>}

            <section className="results-panel">
                <header className="results-header">
                    <h2>Scan Results</h2>
                    <span className="results-count">{results.length} hosts</span>
                </header>
                <div className="table-wrapper">
                    <table className="results-table">
                        <thead>
                        <tr>
                            <th>IP Address</th>
                            <th>Status</th>
                            <th>Latency (ms)</th>
                            <th>Details</th>
                        </tr>
                        </thead>
                        <tbody>
                        {results.length === 0 ? (
                            <tr>
                                <td colSpan={4} className="empty-state">No scan data yet. Start a scan to populate results.</td>
                            </tr>
                        ) : (
                            results.map((item) => (
                                <tr key={item.ip}>
                                    <td>{item.ip}</td>
                                    <td>
                                        <span className={item.reachable ? 'badge badge-success' : 'badge badge-failure'}>
                                            {item.reachable ? 'Reachable' : 'No response'}
                                        </span>
                                    </td>
                                    <td>{item.reachable ? item.latencyMs.toFixed(2) : '—'}</td>
                                    <td>{item.error ?? '—'}</td>
                                </tr>
                            ))
                        )}
                        </tbody>
                    </table>
                </div>
            </section>
        </div>
    );
}

export default App;
