"""
OpsTrace Backend — Dependency Engine
Phase 11: Dependency and Impact Analysis
"""

import uuid
from typing import List, Set, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError
import logging

from backend.app.models.service import Service
from backend.app.models.service_dependency import ServiceDependency
from backend.app.schemas.dependency import DependencyImpactAnalysis, DependencyNode

logger = logging.getLogger(__name__)


class DependencyEngine:
    """
    Phase 11 Dependency and Impact Analysis Engine.
    Provides graph traversal for upstream root causes and downstream blast radius.
    """

    def analyze_impact(
        self,
        db: Session,
        service_id: uuid.UUID,
        max_depth: int = 5,
    ) -> DependencyImpactAnalysis:
        """
        Analyze both upstream dependencies and downstream impacts for a given service.
        """
        service = db.query(Service).filter(Service.id == service_id).first()
        if not service:
            raise ValueError(f"Service with id {service_id} not found")

        downstream = self._get_downstream_impacts(db, service_id, max_depth)
        upstream = self._get_upstream_dependencies(db, service_id, max_depth)

        return DependencyImpactAnalysis(
            service_id=service.id,
            service_name=service.name,
            downstream_impacts=downstream,
            upstream_dependencies=upstream,
        )

    def _get_downstream_impacts(
        self, db: Session, target_service_id: uuid.UUID, max_depth: int
    ) -> List[DependencyNode]:
        """
        Find all services that depend on target_service_id (Blast Radius).
        target_service_id is the provider (depends_on_service_id).
        """
        results: List[DependencyNode] = []
        visited: Set[uuid.UUID] = {target_service_id}
        queue: List[Dict[str, Any]] = [{"id": target_service_id, "depth": 1}]

        while queue:
            current = queue.pop(0)
            curr_id = current["id"]
            curr_depth = current["depth"]

            if curr_depth > max_depth:
                continue

            # Find all edges where depends_on_service_id == curr_id
            edges = (
                db.query(ServiceDependency)
                .filter(ServiceDependency.depends_on_service_id == curr_id)
                .all()
            )

            for edge in edges:
                if edge.service_id not in visited:
                    visited.add(edge.service_id)
                    
                    service = db.query(Service).filter(Service.id == edge.service_id).first()
                    if service:
                        node = DependencyNode(
                            service_id=service.id,
                            service_name=service.name,
                            host_id=service.host_id,
                            host_name=service.host.hostname if service.host else "unknown",
                            criticality=edge.criticality,
                            dependency_type=edge.dependency_type,
                            depth=curr_depth,
                        )
                        results.append(node)
                        queue.append({"id": service.id, "depth": curr_depth + 1})

        return results

    def _get_upstream_dependencies(
        self, db: Session, target_service_id: uuid.UUID, max_depth: int
    ) -> List[DependencyNode]:
        """
        Find all services that target_service_id depends on (Root Causes).
        target_service_id is the caller (service_id).
        """
        results: List[DependencyNode] = []
        visited: Set[uuid.UUID] = {target_service_id}
        queue: List[Dict[str, Any]] = [{"id": target_service_id, "depth": 1}]

        while queue:
            current = queue.pop(0)
            curr_id = current["id"]
            curr_depth = current["depth"]

            if curr_depth > max_depth:
                continue

            # Find all edges where service_id == curr_id
            edges = (
                db.query(ServiceDependency)
                .filter(ServiceDependency.service_id == curr_id)
                .all()
            )

            for edge in edges:
                if edge.depends_on_service_id not in visited:
                    visited.add(edge.depends_on_service_id)
                    
                    service = db.query(Service).filter(Service.id == edge.depends_on_service_id).first()
                    if service:
                        node = DependencyNode(
                            service_id=service.id,
                            service_name=service.name,
                            host_id=service.host_id,
                            host_name=service.host.hostname if service.host else "unknown",
                            criticality=edge.criticality,
                            dependency_type=edge.dependency_type,
                            depth=curr_depth,
                        )
                        results.append(node)
                        queue.append({"id": service.id, "depth": curr_depth + 1})

        return results
