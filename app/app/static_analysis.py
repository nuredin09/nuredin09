"""
Simple static analysis for APKs.

Tries to use androguard if available for best results; otherwise performs
basic checks by reading the APK zip and looking for AndroidManifest.xml and flutter assets.
"""
import os
from zipfile import ZipFile

# Try to use androguard if installed (stronger analysis)
try:
    from androguard.core.bytecodes.apk import APK  # type: ignore
    _HAS_ANDROGUARD = True
except Exception:
    _HAS_ANDROGUARD = False

def analyze_apk(apk_path: str) -> dict:
    findings = []
    metadata = {"apk": apk_path}

    if not os.path.exists(apk_path):
        findings.append({"type": "error", "message": "APK not found"})
        return {"metadata": metadata, "findings": findings}

    metadata["size_bytes"] = os.path.getsize(apk_path)

    if _HAS_ANDROGUARD:
        try:
            a = APK(apk_path)
            metadata["package"] = a.get_package()
            metadata["permissions"] = a.get_permissions()
            findings.append({"type": "info", "message": f"Parsed APK with androguard; package={metadata.get('package')}"})
            # exported components (activities/services/providers/receivers)
            exported = []
            for comp_type in ("activities", "services", "receivers", "providers"):
                items = getattr(a, f"get_{comp_type}")()
                for item in items:
                    # androguard returns full names; manually check exported flag if possible
                    # fallback: add items to exported list and let team refine later
                    exported.append({"type": comp_type[:-1], "name": item})
            metadata["exported_components_count"] = len(exported)
            findings.append({"type": "info", "message": f"Found {len(exported)} components (see metadata)."})
        except Exception as e:
            findings.append({"type": "warning", "message": f"Androguard parse failed: {e}"})
    else:
        # Basic zip inspection
        try:
            with ZipFile(apk_path, "r") as z:
                namelist = z.namelist()
                if "AndroidManifest.xml" in namelist:
                    findings.append({"type": "info", "message": "AndroidManifest.xml present (binary format may require androguard)."})
                else:
                    findings.append({"type": "warning", "message": "AndroidManifest.xml not found in APK (unexpected)."})
                # detect flutter app assets
                if any(n.startswith("assets/flutter_assets/") for n in namelist):
                    findings.append({"type": "info", "message": "Flutter assets detected (likely a Flutter app)."})
        except Exception as e:
            findings.append({"type": "error", "message": f"Failed to read APK zip: {e}"})

    # Simple OWASP-lean checks (examples)
    # - Presence of dangerous permissions
    dangerous_perms = {"android.permission.SEND_SMS", "android.permission.RECORD_AUDIO", "android.permission.READ_SMS"}
    perms = set(metadata.get("permissions", []))
    if perms & dangerous_perms:
        findings.append({"type": "warning", "message": f"Dangerous permissions requested: {', '.join(perms & dangerous_perms)}"})

    return {"metadata": metadata, "findings": findings}
