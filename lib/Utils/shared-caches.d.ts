/** Entry-count budgets for one socket's private caches. */
export type CachePresetShape = {
    session: number;
    senderKey: number;
    recentMessages: number;
    baseKeys: number;
    retry: number;
};
export type CachePresetName = 'tiny' | 'small' | 'medium' | 'large';
/** A preset name, a partial override, or undefined (= 'large'). */
export type CachePresetInput = CachePresetName | Partial<CachePresetShape> | undefined;
/**
 * Per-socket view over a shared pool. Implements both the NodeCache surface
 * (`get`/`mget`/`set`/`mset`/`del`/`keys`/`flushAll`/`close`) and the
 * lru-cache surface (`delete`/`clear`/`size`) so it is a drop-in for either.
 */
export declare class NamespacedCache<V = any> {
    constructor(backing: any, namespace: string);
    get(k: string): V | undefined;
    mget(ks: string[]): Record<string, V>;
    set(k: string, v: V, ttlSeconds?: number): boolean;
    /** Accepts NodeCache's `{key,val,ttl}` and upstream's `{key,value}`. */
    mset(entries: Array<{ key: string; val?: V; value?: V; ttl?: number }>): boolean;
    has(k: string): boolean;
    del(k: string | string[]): number;
    mdel(ks: string[]): number;
    /** Only this namespace's live keys. */
    keys(): string[];
    flushAll(): void;
    /** Drops this socket's entries; leaves the shared pool for other sockets. */
    close(): void;
    delete(k: string): boolean;
    /** Scoped to this namespace — never wipes other sockets. */
    clear(): void;
    readonly size: number;
}
/** One physical LRU shared by many sockets, partitioned by namespace. */
export declare class SharedCache<V = any> {
    constructor(opts?: { max?: number; ttl?: number; updateAgeOnGet?: boolean });
    /** Cheap per-socket view (~a Set, no index arrays). */
    namespace(id: string): NamespacedCache<V>;
    readonly size: number;
    clear(): void;
}
export declare const CACHE_PRESETS: Record<CachePresetName, CachePresetShape>;
export declare const resolveCachePreset: (preset?: CachePresetInput) => CachePresetShape;
export type SharedCacheBundle = {
    session: SharedCache;
    senderKey: SharedCache;
    signalKeys: SharedCache;
    userDevices: SharedCache;
    msgRetry: SharedCache;
    callOffer: SharedCache;
    placeholderResend: SharedCache;
    clear(): void;
};
/**
 * Creates shared cache pools for a multi-tenant process.
 *
 * @example
 * const shared = makeSharedCacheBundle({ maxSockets: 2000 })
 * const sock = makeWASocket({ auth, sharedCaches: shared, cacheId: botId, cachePreset: 'tiny' })
 */
export declare const makeSharedCacheBundle: (opts?: {
    maxSockets?: number;
    entriesPerSocket?: number;
}) => SharedCacheBundle;
/**
 * Shared group-metadata cache for `config.cachedGroupMetadata`. Not namespaced —
 * metadata is identical for every bot in the group, so sharing is the point.
 * Remember to `invalidate()` on `groups.update` / `group-participants.update`.
 */
export declare const makeGroupMetadataCache: (opts?: {
    max?: number;
    ttl?: number;
}) => {
    /** Pass directly as `cachedGroupMetadata`. */
    get: (jid: string) => Promise<any | undefined>;
    set: (jid: string, metadata: any) => void;
    invalidate: (jid: string) => boolean;
    clear: () => void;
    readonly size: number;
};
/** Namespace from the pool when available, else the private fallback. */
export declare const resolveCache: <T>(shared: SharedCacheBundle | undefined, slot: keyof SharedCacheBundle, cacheId: string | undefined, fallbackFactory: () => T) => T | NamespacedCache;
//# sourceMappingURL=shared-caches.d.ts.map
