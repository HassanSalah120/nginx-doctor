"""App Detector - Detects and classifies web applications.

Determines project types (Laravel, PHP MVC, Static, etc.) based on
filesystem structure collected by the scanner.
"""

from dataclasses import dataclass
import json

from nginx_doctor.model.server import ProjectInfo, ProjectType
from nginx_doctor.scanner.filesystem import DirectoryScan


@dataclass
class DetectionResult:
    """Result of app detection."""

    project_type: ProjectType
    confidence: float
    reasons: list[str]
    framework_version: str | None = None


class AppDetector:
    """Detects application frameworks from filesystem scans.

    Does NOT run shell commands - operates on DirectoryScan data only.
    """

    def detect(self, scan: DirectoryScan, composer_json: dict | None = None) -> DetectionResult:
        """Detect the application type from a directory scan.

        Args:
            scan: DirectoryScan from the filesystem scanner.
            composer_json: Parsed composer.json if available.

        Returns:
            DetectionResult with type, confidence, and reasons.
        """
        reasons: list[str] = []
        confidence = 0.0
        project_type = ProjectType.UNKNOWN
        framework_version: str | None = None

        # Check for Laravel
        if scan.has_artisan:
            project_type = ProjectType.LARAVEL
            confidence = 0.90
            reasons.append("Found 'artisan' file (Laravel CLI)")

            if scan.has_public_dir:
                confidence += 0.02
                reasons.append("Has 'public/' directory")
            
            if scan.has_bootstrap_dir:
                confidence += 0.02
                reasons.append("Has 'bootstrap/' directory")
            
            if scan.has_routes_dir:
                confidence += 0.02
                reasons.append("Has 'routes/' directory")
            
            if scan.has_storage_dir:
                confidence += 0.01
                reasons.append("Has 'storage/' directory")
            
            if scan.has_app_dir:
                confidence += 0.01
                reasons.append("Has 'app/' directory")

            if composer_json:
                if self._has_laravel_dependency(composer_json):
                    confidence = min(confidence + 0.02, 1.0)
                    reasons.append("composer.json contains laravel/framework")
                    framework_version = self._get_laravel_version(composer_json)

            return DetectionResult(
                project_type=project_type,
                confidence=min(confidence, 1.0),
                reasons=reasons,
                framework_version=framework_version,
            )


        # Check for generic PHP project
        if scan.has_composer_json or scan.has_index_php:
            project_type = ProjectType.PHP_MVC
            confidence = 0.70
            reasons.append("PHP project detected")

            if scan.has_composer_json:
                reasons.append("Has composer.json")
                confidence += 0.10

            if scan.has_public_dir:
                reasons.append("Has public/ directory (MVC pattern)")
                confidence += 0.10

            return DetectionResult(
                project_type=project_type,
                confidence=confidence,
                reasons=reasons,
            )

        # Check for static site
        if scan.has_index_html:
            project_type = ProjectType.STATIC
            confidence = 0.95
            reasons.append("Static HTML site (has index.html)")

            return DetectionResult(
                project_type=project_type,
                confidence=confidence,
                reasons=reasons,
            )

        # Check for SPA
        if scan.has_package_json:
            project_type = ProjectType.REACT_SPA  # Default to React, could be Vue
            confidence = 0.60
            reasons.append("Has package.json (JavaScript project)")

            # Could check for specific frameworks in package.json
            return DetectionResult(
                project_type=project_type,
                confidence=confidence,
                reasons=reasons,
            )

        # Unknown
        return DetectionResult(
            project_type=ProjectType.UNKNOWN,
            confidence=0.30,
            reasons=["Unable to determine project type"],
        )

    def _has_laravel_dependency(self, composer_json: dict) -> bool:
        """Check if composer.json has Laravel dependency."""
        require = composer_json.get("require", {})
        return "laravel/framework" in require

    def _get_laravel_version(self, composer_json: dict) -> str | None:
        """Extract Laravel version from composer.json."""
        require = composer_json.get("require", {})
        version = require.get("laravel/framework")
        if version:
            # Clean up version constraint (^10.0 -> 10.x)
            version = version.lstrip("^~>=<")
            return f"Laravel {version}"
        return None

    def to_project_info(
        self, scan: DirectoryScan, detection: DetectionResult
    ) -> ProjectInfo:
        """Convert scan and detection result to ProjectInfo."""
        public_path = None
        if scan.has_public_dir:
            public_path = f"{scan.path}/public"

        return ProjectInfo(
            path=scan.path,
            type=detection.project_type,
            confidence=detection.confidence,
            public_path=public_path,
            framework_version=detection.framework_version,
            env_path=f"{scan.path}/.env" if scan.has_env else None,
        )
