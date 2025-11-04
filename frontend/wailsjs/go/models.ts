export namespace scan {
	
	export class Config {
	    subnet: string;
	    threadLimit: number;
	    delayMs: number;
	
	    static createFrom(source: any = {}) {
	        return new Config(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.subnet = source["subnet"];
	        this.threadLimit = source["threadLimit"];
	        this.delayMs = source["delayMs"];
	    }
	}
	export class Progress {
	    total: number;
	    completed: number;
	    active: number;
	    status: string;
	
	    static createFrom(source: any = {}) {
	        return new Progress(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.total = source["total"];
	        this.completed = source["completed"];
	        this.active = source["active"];
	        this.status = source["status"];
	    }
	}
	export class ServiceInfo {
	    port: number;
	    protocol: string;
	    service: string;
	    banner?: string;
	    tlsCertInfo?: string;
	
	    static createFrom(source: any = {}) {
	        return new ServiceInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.port = source["port"];
	        this.protocol = source["protocol"];
	        this.service = source["service"];
	        this.banner = source["banner"];
	        this.tlsCertInfo = source["tlsCertInfo"];
	    }
	}
	export class Result {
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
	    deviceName?: string;
	    macAddress?: string;
	    manufacturer?: string;
	    osGuess?: string;
	    services?: ServiceInfo[];
	    error?: string;
	
	    static createFrom(source: any = {}) {
	        return new Result(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.ip = source["ip"];
	        this.reachable = source["reachable"];
	        this.latencyMs = source["latencyMs"];
	        this.latencySamples = source["latencySamples"];
	        this.attempts = source["attempts"];
	        this.ttl = source["ttl"];
	        this.hostnames = source["hostnames"];
	        this.mdnsNames = source["mdnsNames"];
	        this.netbiosNames = source["netbiosNames"];
	        this.llmnrNames = source["llmnrNames"];
	        this.deviceName = source["deviceName"];
	        this.macAddress = source["macAddress"];
	        this.manufacturer = source["manufacturer"];
	        this.osGuess = source["osGuess"];
	        this.services = this.convertValues(source["services"], ServiceInfo);
	        this.error = source["error"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	export class Snapshot {
	    config: Config;
	    progress: Progress;
	    results: Result[];
	    // Go type: time
	    updated: any;
	
	    static createFrom(source: any = {}) {
	        return new Snapshot(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.config = this.convertValues(source["config"], Config);
	        this.progress = this.convertValues(source["progress"], Progress);
	        this.results = this.convertValues(source["results"], Result);
	        this.updated = this.convertValues(source["updated"], null);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

