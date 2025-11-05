import {ChangeEvent, Fragment, useCallback, useEffect, useMemo, useState} from 'react';
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

interface ServiceInfo {
    port: number;
    protocol: string;
    service: string;
    banner?: string;
    tlsCertInfo?: string;
}

interface AirPlayInfo {
    endpoint?: string;
    fields?: Record<string, string>;
}

interface SMBInfo {
    computerName?: string;
    domain?: string;
    source?: string;
}

interface ScanResult {
    ip: string;
    reachable: boolean;
    latencyMs: number;
    latencySamples?: number[];
    attempts: number;
    ttl?: number;
    hostnames?: string[];
    mdnsNames?: string[];
    netbiosNames?: string[];
    llmnrNames?: string[];
    smbInfo?: SMBInfo;
    deviceName?: string;
    macAddress?: string;
    manufacturer?: string;
    osGuess?: string;
    services?: ServiceInfo[];
    airPlay?: AirPlayInfo;
    discoverySources?: string[];
    insightScore?: number;
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

type SortKey = 'insights' | 'latency' | 'ip';

type ObservationTone = 'info' | 'warn' | 'error' | 'muted' | 'success';

interface Observation {
    label: string;
    tone: ObservationTone;
}

const httpPorts = new Set([
    80,
    81,
    3000,
    3128,
    4200,
    5000,
    5601,
    5984,
    5985,
    7000,
    7547,
    8000,
    8001,
    8002,
    8003,
    8004,
    8005,
    8006,
    8007,
    8008,
    8009,
    8010,
    8080,
    8081,
    8082,
    8083,
    8086,
    8088,
    8530,
    8888,
    9000,
    9200
]);
const httpsPorts = new Set([443, 4443, 5986, 8443, 8729, 9443]);

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
    const [form, setForm] = useState<FormState>({subnet: '192.168.1.0/24', threadLimit: '64', delayMs: '10'});
    const [progress, setProgress] = useState<ScanProgress>(defaultProgress);
    const [results, setResults] = useState<ScanResult[]>([]);
    const [error, setError] = useState<string | null>(null);
    const [busyAction, setBusyAction] = useState<string | null>(null);
    const [showReachableOnly, setShowReachableOnly] = useState<boolean>(true);
    const [showSuccessfulOnly, setShowSuccessfulOnly] = useState<boolean>(false);
    const [minInsightScore, setMinInsightScore] = useState<number>(0);
    const [sortKey, setSortKey] = useState<SortKey>('insights');
    const [expandedRows, setExpandedRows] = useState<Record<string, boolean>>({});

    const isRunning = progress.status === 'running';
    const isPaused = progress.status === 'paused';
    const hasResults = results.length > 0;

    const percentComplete = useMemo(() => {
        if (!progress.total) {
            return 0;
        }
        return Math.min(100, Math.round((progress.completed / progress.total) * 100));
    }, [progress.completed, progress.total]);

    const maxInsightScore = useMemo(
        () => results.reduce((max, item) => Math.max(max, item.insightScore ?? 0), 0),
        [results]
    );

    useEffect(() => {
        if (minInsightScore > maxInsightScore) {
            setMinInsightScore(maxInsightScore);
        }
    }, [maxInsightScore, minInsightScore]);

    const visibleResults = useMemo(() => {
        const dataset = results.filter((item) => {
            if (showReachableOnly && !item.reachable) {
                return false;
            }
            if (showSuccessfulOnly && (!item.reachable || item.error)) {
                return false;
            }
            return (item.insightScore ?? 0) >= minInsightScore;
        });

        return dataset.sort((a, b) => {
            switch (sortKey) {
                case 'latency': {
                    const latencyA = a.reachable ? a.latencyMs : Number.POSITIVE_INFINITY;
                    const latencyB = b.reachable ? b.latencyMs : Number.POSITIVE_INFINITY;
                    return latencyA - latencyB;
                }
                case 'ip':
                    return a.ip.localeCompare(b.ip, undefined, {numeric: true});
                case 'insights':
                default:
                    return (b.insightScore ?? 0) - (a.insightScore ?? 0);
            }
        });
    }, [results, showReachableOnly, showSuccessfulOnly, minInsightScore, sortKey]);

    const totalReachable = useMemo(() => results.filter((item) => item.reachable).length, [results]);

    const formatLatency = (value: number) => {
        if (!Number.isFinite(value) || value <= 0) {
            return '—';
        }
        if (value < 1) {
            return `${value.toFixed(3)}`;
        }
        return value.toFixed(2);
    };

    const summariseServices = (services?: ServiceInfo[]) => {
        if (!services || services.length === 0) {
            return '—';
        }
        const sorted = services.slice().sort((a, b) => a.port - b.port);
        const summary = sorted
            .slice(0, 2)
            .map((svc) => `${svc.service} (${svc.port}/${svc.protocol.toUpperCase()})`)
            .join(', ');
        if (sorted.length > 2) {
            return `${summary} +${sorted.length - 2} more`;
        }
        return summary;
    };

    const renderList = (values?: string[]) => {
        if (!values || values.length === 0) {
            return '—';
        }
        return values.join(', ');
    };

    const renderLatencySamples = (values?: number[]) => {
        if (!values || values.length === 0) {
            return '—';
        }
        return values.map((sample, index) => {
            const formatted = formatLatency(sample);
            const display = formatted === '—' ? formatted : `${formatted} ms`;
            return (
                <span className="latency-chip" key={index}>
                    {display}
                </span>
            );
        });
    };

    const getAirPlayEntries = (info?: AirPlayInfo): [string, string][] => {
        if (!info?.fields) {
            return [];
        }
        return Object.entries(info.fields).sort(([a], [b]) => a.localeCompare(b));
    };

    const getAirPlayField = (info: AirPlayInfo | undefined, key: string): string | undefined => {
        if (!info?.fields) {
            return undefined;
        }
        if (info.fields[key]) {
            return info.fields[key];
        }
        const match = Object.entries(info.fields).find(([entryKey]) => entryKey.toLowerCase() === key.toLowerCase());
        return match?.[1];
    };

    const renderAirPlayMetadata = (info?: AirPlayInfo) => {
        const entries = getAirPlayEntries(info);
        if (!info?.endpoint && entries.length === 0) {
            return null;
        }

        return (
            <dl className="metadata-grid">
                {info?.endpoint && (
                    <>
                        <dt>Source</dt>
                        <dd>{info.endpoint}</dd>
                    </>
                )}
                {entries.map(([key, value]) => (
                    <Fragment key={key}>
                        <dt>{key}</dt>
                        <dd>{value}</dd>
                    </Fragment>
                ))}
            </dl>
        );
    };

    const getPreferredHostname = (item: ScanResult) => {
        const dnsHost = item.hostnames?.find((name) => !!name);
        if (dnsHost) {
            return dnsHost;
        }
        const mdnsHost = item.mdnsNames?.find((name) => !!name);
        if (mdnsHost) {
            return mdnsHost;
        }
        return item.ip;
    };

    const buildServiceUrl = (service: ServiceInfo, item: ScanResult): string | null => {
        if (service.protocol.toLowerCase() !== 'tcp') {
            return null;
        }

        const name = service.service.toLowerCase();
        const hasTls = Boolean(service.tlsCertInfo);
        const isHttpsCandidate = hasTls || httpsPorts.has(service.port) || name.includes('https');
        const isHttpCandidate = httpPorts.has(service.port) || name.includes('http') || name.includes('web');

        if (!isHttpsCandidate && !isHttpCandidate) {
            return null;
        }

        const scheme = isHttpsCandidate ? 'https' : 'http';
        const defaultPort = scheme === 'https' ? 443 : 80;
        const host = getPreferredHostname(item);
        const needsPort = service.port !== defaultPort;
        const portSuffix = needsPort ? `:${service.port}` : '';

        return `${scheme}://${host}${portSuffix}`;
    };

    const buildObservations = (item: ScanResult): Observation[] => {
        const observations: Observation[] = [];
        const addObservation = (observation: Observation) => {
            if (!observations.some((existing) => existing.label === observation.label)) {
                observations.push(observation);
            }
        };

        if (item.error) {
            addObservation({label: item.error, tone: 'error'});
            return observations;
        }

        if (!item.reachable) {
            addObservation({label: 'No response detected', tone: 'muted'});
        } else {
            if (item.latencyMs > 0 && item.latencyMs <= 5) {
                addObservation({label: 'Very low latency', tone: 'success'});
            } else if (item.latencyMs > 120) {
                addObservation({label: `High latency (${formatLatency(item.latencyMs)} ms)`, tone: 'warn'});
            }
        }

        const hostnameLabel = item.hostnames?.[0] ?? item.mdnsNames?.[0];
        if (hostnameLabel) {
            addObservation({label: `Hostname: ${hostnameLabel}`, tone: 'info'});
        }

        if (item.smbInfo?.computerName) {
            addObservation({label: `SMB workstation: ${item.smbInfo.computerName}`, tone: 'info'});
        }

        if (item.smbInfo?.domain) {
            addObservation({label: `SMB domain: ${item.smbInfo.domain}`, tone: 'muted'});
        }

        if (item.discoverySources && item.discoverySources.length > 0) {
            const preferredSources = item.discoverySources.slice(0, 2);
            preferredSources.forEach((source) => {
                addObservation({label: `Seen via ${source}`, tone: 'muted'});
            });
        }

        if (item.services && item.services.length > 0) {
            item.services.forEach((service) => {
                const name = service.service.toLowerCase();
                if (service.port === 3389 || name.includes('rdp')) {
                    addObservation({label: 'RDP exposed', tone: 'warn'});
                }
                if (service.port === 445 || name.includes('smb')) {
                    addObservation({label: 'SMB file sharing', tone: 'warn'});
                }
                if (service.port === 22 || name.includes('ssh')) {
                    addObservation({label: 'SSH remote access', tone: 'info'});
                }
                if (service.port === 21 || name.includes('ftp')) {
                    addObservation({label: 'FTP (unencrypted)', tone: 'warn'});
                }
                if (service.port === 23 || name.includes('telnet')) {
                    addObservation({label: 'Telnet (unencrypted)', tone: 'warn'});
                }
                if (service.port === 25 || name.includes('smtp')) {
                    addObservation({label: 'SMTP service', tone: 'info'});
                }
                if (httpsPorts.has(service.port) || name.includes('https') || service.tlsCertInfo) {
                    addObservation({label: `HTTPS on ${service.port}`, tone: 'success'});
                } else if (httpPorts.has(service.port) || name.includes('http')) {
                    addObservation({label: `HTTP on ${service.port}`, tone: 'warn'});
                }
                if (service.port === 161 || name.includes('snmp')) {
                    addObservation({label: 'SNMP management interface', tone: 'info'});
                }
                if (service.port === 5985 || service.port === 5986 || name.includes('winrm')) {
                    addObservation({label: 'WinRM remote management', tone: 'warn'});
                }
                if (service.port === 7547 || name.includes('tr-069')) {
                    addObservation({label: 'TR-069 remote management', tone: 'warn'});
                }
                if (service.port === 8291 || name.includes('winbox')) {
                    addObservation({label: 'MikroTik WinBox service', tone: 'warn'});
                }
                if (service.port === 8728 || service.port === 8729 || name.includes('mikrotik')) {
                    addObservation({label: 'MikroTik API endpoint', tone: 'info'});
                }
                if (service.port === 515 || name.includes('lpd')) {
                    addObservation({label: 'LPD printing available', tone: 'info'});
                }
                if (service.port === 9100 || name.includes('jetdirect') || name.includes('printer')) {
                    addObservation({label: 'Printer raw port (JetDirect)', tone: 'info'});
                }
                if (service.port === 3306 || name.includes('mysql')) {
                    addObservation({label: 'MySQL database service', tone: 'info'});
                }
                if (service.port === 5432 || name.includes('postgres')) {
                    addObservation({label: 'PostgreSQL database service', tone: 'info'});
                }
                if (service.port === 1433 || name.includes('mssql')) {
                    addObservation({label: 'Microsoft SQL Server', tone: 'info'});
                }
                if (service.port === 6379 || name.includes('redis')) {
                    addObservation({label: 'Redis data store', tone: 'info'});
                }
                if (service.port === 27017 || name.includes('mongo')) {
                    addObservation({label: 'MongoDB database', tone: 'info'});
                }
                if (service.port === 9200 || name.includes('elastic')) {
                    addObservation({label: 'Elasticsearch endpoint', tone: 'info'});
                }
                if (service.banner) {
                    const banner = service.banner.toLowerCase();
                    if (banner.includes('openssh')) {
                        addObservation({label: 'OpenSSH banner', tone: 'info'});
                    } else if (banner.includes('microsoft')) {
                        addObservation({label: 'Microsoft service banner', tone: 'info'});
                    }
                }
            });
        }

        if (item.airPlay?.fields && Object.keys(item.airPlay.fields).length > 0) {
            const model =
                getAirPlayField(item.airPlay, 'model') ??
                getAirPlayField(item.airPlay, 'hwmodel') ??
                getAirPlayField(item.airPlay, 'deviceid') ??
                getAirPlayField(item.airPlay, 'name');
            if (model) {
                addObservation({label: `AirPlay: ${model}`, tone: 'info'});
            } else {
                addObservation({label: 'AirPlay service metadata', tone: 'info'});
            }
        }

        if (item.osGuess && item.osGuess !== 'Unknown') {
            addObservation({label: `OS likely ${item.osGuess}`, tone: 'info'});
        }

        return observations.slice(0, 5);
    };

    const toggleExpanded = (ip: string) => {
        setExpandedRows((prev) => ({...prev, [ip]: !prev[ip]}));
    };

    const insightPresets = useMemo(() => {
        return [
            {label: 'All data', value: 0},
            {label: 'Enriched (≥5)', value: Math.min(5, maxInsightScore)},
            {label: 'Deep scan (≥10)', value: Math.min(10, maxInsightScore)}
        ];
    }, [maxInsightScore]);

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
                <div className="summary-item">
                    <span className="summary-label">Reachable Hosts</span>
                    <span className="summary-value">{totalReachable} / {results.length}</span>
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
                    <div className="results-controls">
                        <label className="filter-toggle">
                            <input
                                type="checkbox"
                                checked={showReachableOnly}
                                onChange={(event) => setShowReachableOnly(event.target.checked)}
                            />
                            Reachable only
                        </label>
                        <label className="filter-toggle">
                            <input
                                type="checkbox"
                                checked={showSuccessfulOnly}
                                onChange={(event) => setShowSuccessfulOnly(event.target.checked)}
                            />
                            Successful only
                        </label>
                        <div className="insight-filter">
                            <label htmlFor="insight-range">Minimum insights: {minInsightScore}</label>
                            <input
                                id="insight-range"
                                type="range"
                                min={0}
                                max={Math.max(maxInsightScore, 1)}
                                value={Math.min(minInsightScore, Math.max(maxInsightScore, 1))}
                                onChange={(event) => setMinInsightScore(Number.parseInt(event.target.value, 10))}
                                disabled={!results.length}
                            />
                            <div className="insight-presets">
                                {insightPresets.map((preset) => (
                                    <button
                                        key={preset.label}
                                        type="button"
                                        className={preset.value === minInsightScore ? 'preset active' : 'preset'}
                                        onClick={() => setMinInsightScore(preset.value)}
                                        disabled={!results.length}
                                    >
                                        {preset.label}
                                    </button>
                                ))}
                            </div>
                        </div>
                        <div className="sort-control">
                            <label htmlFor="sort-key">Sort</label>
                            <select
                                id="sort-key"
                                value={sortKey}
                                onChange={(event) => setSortKey(event.target.value as SortKey)}
                            >
                                <option value="insights">Highest insights</option>
                                <option value="latency">Lowest latency</option>
                                <option value="ip">IP address</option>
                            </select>
                        </div>
                        <span className="results-count">{visibleResults.length} / {results.length} hosts</span>
                    </div>
                </header>
                <div className="table-wrapper">
                    <table className="results-table">
                        <thead>
                        <tr>
                            <th aria-label="Expand" />
                            <th>Device</th>
                            <th>IP Address</th>
                            <th>MAC</th>
                            <th>Manufacturer</th>
                            <th>OS</th>
                            <th>Latency (ms)</th>
                            <th>Services</th>
                            <th>Insights</th>
                            <th>Status</th>
                            <th>Notes</th>
                        </tr>
                        </thead>
                        <tbody>
                        {results.length === 0 ? (
                            <tr>
                                <td colSpan={11} className="empty-state">No scan data yet. Start a scan to populate results.</td>
                            </tr>
                        ) : visibleResults.length === 0 ? (
                            <tr>
                                <td colSpan={11} className="empty-state">No results match the current filters.</td>
                            </tr>
                        ) : (
                            visibleResults.map((item) => {
                                const expanded = !!expandedRows[item.ip];
                                const insightScore = item.insightScore ?? 0;
                                const insightPercent = maxInsightScore > 0 ? Math.round((insightScore / maxInsightScore) * 100) : 0;
                                const insightSources = item.discoverySources ?? [];
                                const observations = buildObservations(item);
                                const airPlayMetadata = renderAirPlayMetadata(item.airPlay);
                                return (
                                    <>
                                        <tr key={`${item.ip}-summary`} className={expanded ? 'expanded' : ''}>
                                            <td>
                                                <button
                                                    type="button"
                                                    className="expand-toggle"
                                                    onClick={() => toggleExpanded(item.ip)}
                                                    aria-expanded={expanded}
                                                    aria-controls={`${item.ip}-details`}
                                                >
                                                    {expanded ? 'Hide' : 'View'}
                                                </button>
                                            </td>
                                            <td>
                                            <div className="device-name">{item.deviceName ?? '—'}</div>
                                            <div className="device-aliases">
                                                {[
                                                    ...(item.mdnsNames ?? []),
                                                    ...(item.hostnames ?? []),
                                                    ...(item.smbInfo?.computerName ? [item.smbInfo.computerName] : [])
                                                ]
                                                    .filter((value, index, array) => array.indexOf(value) === index)
                                                    .join(', ') || '—'}
                                            </div>
                                        </td>
                                            <td>{item.ip}</td>
                                            <td className="mono">{item.macAddress ?? '—'}</td>
                                            <td>{item.manufacturer ?? '—'}</td>
                                            <td>{item.osGuess ?? '—'}</td>
                                            <td>{item.reachable ? formatLatency(item.latencyMs) : '—'}</td>
                                            <td>{summariseServices(item.services)}</td>
                                            <td>
                                                <div className="insight-score-cell">
                                                    <div className="score-header">
                                                        <span className="score-value">{insightScore}</span>
                                                        <span className="score-label">score</span>
                                                    </div>
                                                    <div className="score-bar">
                                                        <div style={{width: `${insightPercent}%`}} />
                                                    </div>
                                                    <div className="score-sources">
                                                        {insightSources.length > 0 ? insightSources.slice(0, 3).join(', ') : '—'}
                                                    </div>
                                                </div>
                                            </td>
                                            <td>
                                                <span className={item.reachable ? 'badge badge-success' : 'badge badge-failure'}>
                                                    {item.reachable ? 'Reachable' : 'No response'}
                                                </span>
                                            </td>
                                            <td>
                                                {observations.length > 0 ? (
                                                    <div className="observation-pills">
                                                        {observations.map((observation) => (
                                                            <span
                                                                key={observation.label}
                                                                className={`observation-pill tone-${observation.tone}`}
                                                            >
                                                                {observation.label}
                                                            </span>
                                                        ))}
                                                    </div>
                                                ) : (
                                                    <span className="meta">No observations</span>
                                                )}
                                            </td>
                                        </tr>
                                        {expanded && (
                                            <tr className="expanded-row" id={`${item.ip}-details`} key={`${item.ip}-details`}>
                                                <td colSpan={11}>
                                                    <div className="detail-grid">
                                                        <div className="detail-card">
                                                            <h3>Network identity</h3>
                                                            <ul>
                                                                <li><span>IP:</span> {item.ip}</li>
                                                                <li><span>MAC:</span> {item.macAddress ?? '—'}</li>
                                                                <li><span>Manufacturer:</span> {item.manufacturer ?? '—'}</li>
                                                                <li><span>Device name:</span> {item.deviceName ?? '—'}</li>
                                                                {item.smbInfo?.computerName && (
                                                                    <li><span>SMB name:</span> {item.smbInfo.computerName}</li>
                                                                )}
                                                                {item.smbInfo?.domain && (
                                                                    <li><span>SMB domain:</span> {item.smbInfo.domain}</li>
                                                                )}
                                                                {item.smbInfo?.source && (
                                                                    <li><span>SMB source:</span> {item.smbInfo.source}</li>
                                                                )}
                                                                <li><span>OS guess:</span> {item.osGuess ?? '—'}</li>
                                                                <li><span>TTL:</span> {item.ttl ?? '—'}</li>
                                                                <li><span>Checks:</span> {item.attempts}</li>
                                                            </ul>
                                                        </div>
                                                        <div className="detail-card">
                                                            <h3>Latency</h3>
                                                            <p><strong>Average:</strong> {item.reachable ? `${formatLatency(item.latencyMs)} ms` : '—'}</p>
                                                            <div className="latency-samples-wrapper">{renderLatencySamples(item.latencySamples)}</div>
                                                        </div>
                                                        <div className="detail-card">
                                                            <h3>Discovery sources</h3>
                                                            <div className="source-badges">
                                                                {insightSources.length > 0
                                                                    ? insightSources.map((source) => (
                                                                          <span className="source-badge" key={source}>
                                                                              {source}
                                                                          </span>
                                                                      ))
                                                                    : '—'}
                                                            </div>
                                                        </div>
                                                    </div>
                                                    <div className="detail-grid two-column">
                                                        <div className="detail-card">
                                                            <h3>Hostnames</h3>
                                                            <dl>
                                                                <dt>DNS</dt>
                                                                <dd>{renderList(item.hostnames)}</dd>
                                                                <dt>mDNS</dt>
                                                                <dd>{renderList(item.mdnsNames)}</dd>
                                                                <dt>NetBIOS</dt>
                                                                <dd>{renderList(item.netbiosNames)}</dd>
                                                                <dt>SMB</dt>
                                                                <dd>{item.smbInfo?.computerName ?? '—'}</dd>
                                                                <dt>SMB domain</dt>
                                                                <dd>{item.smbInfo?.domain ?? '—'}</dd>
                                                                <dt>LLMNR</dt>
                                                                <dd>{renderList(item.llmnrNames)}</dd>
                                                            </dl>
                                                        </div>
                                                        {airPlayMetadata && (
                                                            <div className="detail-card">
                                                                <h3>AirPlay metadata</h3>
                                                                {airPlayMetadata}
                                                            </div>
                                                        )}
                                                        <div className="detail-card">
                                                            <h3>Services ({item.services?.length ?? 0})</h3>
                                                            {item.services && item.services.length > 0 ? (
                                                                <ul className="service-list">
                                                                    {item.services.map((service) => {
                                                                        const serviceLabel = `${service.service} (${service.port}/${service.protocol.toUpperCase()})`;
                                                                        const serviceUrl = buildServiceUrl(service, item);
                                                                        return (
                                                                            <li key={`${service.protocol}-${service.port}-${service.service}`}>
                                                                                <div className="service-header">
                                                                                    {serviceUrl ? (
                                                                                        <a
                                                                                            href={serviceUrl}
                                                                                            target="_blank"
                                                                                            rel="noopener noreferrer"
                                                                                            className="service-link"
                                                                                        >
                                                                                            {serviceLabel}
                                                                                        </a>
                                                                                    ) : (
                                                                                        <span>{serviceLabel}</span>
                                                                                    )}
                                                                                    {service.tlsCertInfo && (
                                                                                        <span className="tls-chip">TLS</span>
                                                                                    )}
                                                                                </div>
                                                                                {service.banner && <div className="service-banner">{service.banner}</div>}
                                                                                {service.tlsCertInfo && (
                                                                                    <div className="service-banner tls">{service.tlsCertInfo}</div>
                                                                                )}
                                                                            </li>
                                                                        );
                                                                    })}
                                                                </ul>
                                                            ) : (
                                                                <p>—</p>
                                                            )}
                                                        </div>
                                                    </div>
                                                    <div className="detail-card full-width">
                                                        <h3>Raw record</h3>
                                                        <pre className="raw-json">{JSON.stringify(item, null, 2)}</pre>
                                                    </div>
                                                </td>
                                            </tr>
                                        )}
                                    </>
                                );
                            })
                        )}
                        </tbody>
                    </table>
                </div>
            </section>
        </div>
    );
}

export default App;
