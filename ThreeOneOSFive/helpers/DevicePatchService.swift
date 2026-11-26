import Foundation

enum DevicePatchService {
    static func apply(project: PatchProject) throws -> PatchTransactionReceipt {
        log("patch: apply begin project=\(project.id.uuidString) bundles=\(project.allBundleIdentifiers)")
        try ensureSandboxAccessForPatching()
        log("patch: sandbox check passed")
        let bundleIDs = orderedBundleIdentifiers(in: project)
        return try withResolvedContainers(bundleIDs: bundleIDs) { roots in
            log("patch: resolved containers count=\(roots.count)")
            try PatchTransaction.apply(
                project: project,
                backupRoot: try PatchProjectLibrary.backupRootURL(),
                containerResolver: { bundleID in
                    guard let root = roots[bundleID] else {
                        throw PatchPackageError.targetAppUnavailable(bundleID)
                    }
                    return root
                }
            )
        }
    }

    static func restore(receipt: PatchTransactionReceipt) throws {
        log("patch: restore begin receipt=\(receipt.id.uuidString)")
        try ensureSandboxAccessForPatching()
        log("patch: sandbox check passed for restore")
        let bundleIDs = try PatchTransaction.requiredBundleIdentifiers(for: receipt)
        try withResolvedContainers(bundleIDs: bundleIDs) { roots in
            log("patch: resolved restore containers count=\(roots.count)")
            try PatchTransaction.restore(
                receipt: receipt,
                containerResolver: { bundleID in
                    guard let root = roots[bundleID] else {
                        throw PatchPackageError.targetAppUnavailable(bundleID)
                    }
                    return root
                }
            )
        }
    }

    static func latestReceipt(projectID: UUID) -> PatchTransactionReceipt? {
        guard let backupRoot = try? PatchProjectLibrary.backupRootURL() else { return nil }
        return PatchTransaction.latestReceipt(projectID: projectID, backupRoot: backupRoot)
    }

    /// iOS 26+/27: container resolve + file write need full sandbox escape.
    private static func ensureSandboxAccessForPatching() throws {
        guard KernelExploit.requiresSandboxEscape else { return }

        if KernelExploit.hasSandboxAccess() {
            log("patch: sandbox access already active")
            return
        }

        log("patch: sandbox access missing — running kernel exploit before apply/restore")
        let ok = KernelExploit.run()
        if ok, KernelExploit.hasSandboxAccess() {
            log("patch: sandbox access established after exploit")
            return
        }

        log("patch: sandbox access still inactive after exploit (ok=\(ok))")
        throw PatchPackageError.sandboxAccessRequired
    }

    private static func orderedBundleIdentifiers(in project: PatchProject) -> [String] {
        project.allBundleIdentifiers
    }

    private static func withResolvedContainers<T>(
        bundleIDs: [String],
        operation: ([String: URL]) throws -> T
    ) throws -> T {
        var roots: [String: URL] = [:]

        for bundleID in bundleIDs {
            if let path = resolveContainerPathRobust(bundleID: bundleID) {
                roots[bundleID] = PatchPathValidator.canonicalFileURL(
                    URL(fileURLWithPath: path, isDirectory: true)
                )
                continue
            }

            // Diagnostic: distinguish "not installed" vs "installed but unreadable"
            let installedHint = freefireInstalledHint(lookingFor: bundleID)
            log("patch: resolve failed for \(bundleID) sandbox=\(KernelExploit.hasSandboxAccess()) \(installedHint)")

            if KernelExploit.requiresSandboxEscape, !KernelExploit.hasSandboxAccess() {
                throw PatchPackageError.sandboxAccessRequired
            }
            throw PatchPackageError.targetAppUnavailable(bundleID)
        }
        return try operation(roots)
    }

    /// MCM first, then metadata scan, then installed-apps API map, then grant+retry.
    private static func resolveContainerPathRobust(bundleID: String) -> String? {
        func acceptable(_ path: String) -> Bool {
            ContainerStore.isApplicationContainerPath(path)
                || ContainerStore.looksLikeAppDataContainer(path)
        }

        if let path = ContainerStore.resolveAppContainerPath(bundleID: bundleID), acceptable(path) {
            log("patch: resolved \(bundleID) via primary → \(path)")
            return path
        }

        // Direct LS lookup for this exact ID
        if let info = appInfoForBundleID(bundleID) as? [String: Any],
           let path = info["container"] as? String,
           !path.isEmpty,
           acceptable(path) {
            log("patch: resolved \(bundleID) via appInfoForBundleID → \(path)")
            return path
        }

        // API catalog sometimes has the container even when MCM activate fails.
        for app in ContainerStore.installedAppsFromAPI() where app.bundleID == bundleID {
            let path = app.containerPath
            if acceptable(path) {
                    log("patch: resolved \(bundleID) via LS/API catalog → \(path)")
                return path
            }
        }

        // Last resort: full filesystem metadata walk (needs sandbox escape on 26+).
        if let path = ContainerStore.resolveAppContainerPathByMetadataScan(bundleID: bundleID),
           acceptable(path) {
            log("patch: resolved \(bundleID) via metadata scan → \(path)")
            return path
        }

        return nil
    }

    /// Helps logs: is any Free Fire variant visible to the tool?
    private static func freefireInstalledHint(lookingFor: String) -> String {
        let apps = ContainerStore.installedAppsFromAPI()
        let ff = apps.filter {
            $0.bundleID.lowercased().contains("freefire")
                || $0.bundleID.lowercased().contains("dts.free")
        }
        if ff.isEmpty {
            // metadata scan sample (expensive only on failure path)
            if KernelExploit.hasSandboxAccess() || !KernelExploit.requiresSandboxEscape {
                let dirs = ContainerStore.enumerateDirectoriesPublic()
                var found: [String] = []
                for dir in dirs.prefix(400) {
                    guard let meta = ContainerStore.readContainerMetadata(containerPath: dir) else { continue }
                    let bid = meta.bundleID.lowercased()
                    if bid.contains("freefire") || bid.contains("dts.free") {
                        found.append(meta.bundleID)
                    }
                }
                if !found.isEmpty {
                    return "freefire-in-metadata=\(Array(Set(found)).sorted()) lookingFor=\(lookingFor)"
                }
            }
            return "no-freefire-visible lookingFor=\(lookingFor)"
        }
        return "freefire-visible=\(ff.map { "\($0.bundleID)[\($0.containerPath.isEmpty ? "no-path" : "path")]" }) lookingFor=\(lookingFor)"
    }
}

// Minimal surface so DevicePatchService can call directory enumeration without
// exposing the whole private API surface of ContainerStore.
extension ContainerStore {
    static func enumerateDirectoriesPublic() -> [String] {
        enumerateDirectories(path: appDataRoot)
    }
}
