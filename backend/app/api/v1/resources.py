"""
OpsTrace API v1 — Observability Resources Router
Phase 12: React Dashboard Layer

Exposes READ-ONLY REST API endpoints for key operational resources:
  - GET /api/v1/hosts
  - GET /api/v1/services
  - GET /api/v1/incidents
  - GET /api/v1/incidents/{incident_id}
  - GET /api/v1/remediations
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.models import Host, Service, Incident, Remediation

logger = logging.getLogger(__name__)

router = APIRouter(tags=["resources"])


@router.get(
    "/hosts",
    status_code=status.HTTP_200_OK,
    summary="List monitored hosts",
    description="Returns all monitored hosts and their basic metadata and status.",
)
def list_hosts(
    db: Session = Depends(get_db),
    status_filter: Optional[str] = Query(default=None, alias="status"),
) -> List[Dict[str, Any]]:
    query = db.query(Host)
    if status_filter:
        query = query.filter(Host.status == status_filter)
    hosts = query.order_by(Host.created_at.desc()).all()

    result = []
    for h in hosts:
        result.append({
            "id": str(h.id),
            "hostname": h.hostname,
            "ip_address": h.ip_address,
            "status": h.status,
            "os_info": h.os_info,
            "kernel_version": h.kernel_version,
            "cpu_count": h.cpu_count,
            "total_memory_bytes": h.total_memory_bytes,
            "total_disk_bytes": h.total_disk_bytes,
            "agent_version": h.agent_version,
            "last_heartbeat_at": h.last_heartbeat_at.isoformat() if h.last_heartbeat_at else None,
            "created_at": h.created_at.isoformat() if h.created_at else None,
            "updated_at": h.updated_at.isoformat() if h.updated_at else None,
            "services_count": len(h.services) if h.services else 0,
        })
    return result


@router.get(
    "/services",
    status_code=status.HTTP_200_OK,
    summary="List monitored services",
    description="Returns all monitored services, their host associations, and health status.",
)
def list_services(
    db: Session = Depends(get_db),
    host_id: Optional[uuid.UUID] = Query(default=None),
) -> List[Dict[str, Any]]:
    query = db.query(Service)
    if host_id:
        query = query.filter(Service.host_id == host_id)
    services = query.order_by(Service.name.asc()).all()

    result = []
    for s in services:
        result.append({
            "id": str(s.id),
            "name": s.name,
            "host_id": str(s.host_id) if s.host_id else None,
            "hostname": s.host.hostname if s.host else None,
            "service_type": s.service_type,
            "port": s.port,
            "status": s.status,
            "description": s.description,
            "systemd_unit": s.systemd_unit,
            "created_at": s.created_at.isoformat() if s.created_at else None,
            "updated_at": s.updated_at.isoformat() if s.updated_at else None,
        })
    return result


@router.get(
    "/incidents",
    status_code=status.HTTP_200_OK,
    summary="List incidents",
    description="Returns all recorded incidents with optional filtering by status and severity.",
)
def list_incidents(
    db: Session = Depends(get_db),
    status_filter: Optional[str] = Query(default=None, alias="status"),
    severity_filter: Optional[str] = Query(default=None, alias="severity"),
) -> List[Dict[str, Any]]:
    query = db.query(Incident)
    if status_filter:
        query = query.filter(Incident.status == status_filter)
    if severity_filter:
        query = query.filter(Incident.severity == severity_filter)
    incidents = query.order_by(Incident.created_at.desc()).all()

    result = []
    for inc in incidents:
        result.append({
            "id": str(inc.id),
            "title": inc.title,
            "description": inc.description,
            "status": inc.status,
            "severity": inc.severity,
            "host_id": str(inc.host_id) if inc.host_id else None,
            "service_id": str(inc.service_id) if inc.service_id else None,
            "detected_at": inc.detected_at.isoformat() if inc.detected_at else (inc.created_at.isoformat() if inc.created_at else None),
            "created_at": inc.created_at.isoformat() if inc.created_at else None,
            "updated_at": inc.updated_at.isoformat() if inc.updated_at else None,
            "resolved_at": inc.resolved_at.isoformat() if inc.resolved_at else None,
        })
    return result


@router.get(
    "/incidents/{incident_id}",
    status_code=status.HTTP_200_OK,
    summary="Get single incident details",
    description="Returns detailed information for a single incident.",
)
def get_incident(
    incident_id: uuid.UUID,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if not inc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found.",
        )
    return {
        "id": str(inc.id),
        "title": inc.title,
        "description": inc.description,
        "status": inc.status,
        "severity": inc.severity,
        "host_id": str(inc.host_id) if inc.host_id else None,
        "service_id": str(inc.service_id) if inc.service_id else None,
        "hostname": inc.host.hostname if inc.host else None,
        "service_name": inc.service.name if inc.service else None,
        "detected_at": inc.detected_at.isoformat() if inc.detected_at else (inc.created_at.isoformat() if inc.created_at else None),
        "created_at": inc.created_at.isoformat() if inc.created_at else None,
        "updated_at": inc.updated_at.isoformat() if inc.updated_at else None,
        "resolved_at": inc.resolved_at.isoformat() if inc.resolved_at else None,
        "root_cause_analysis": inc.root_cause_analysis,
        "correlated_deployment_id": str(inc.correlated_deployment_id) if inc.correlated_deployment_id else None,
        "correlated_config_change_id": str(inc.correlated_config_change_id) if inc.correlated_config_change_id else None,
        "remediations": [
            {
                "id": str(r.id),
                "action_type": r.action_type,
                "description": r.description,
                "status": r.status,
                "requested_by": r.requested_by,
                "approved_by": r.approved_by,
                "execution_output": r.execution_output,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in (inc.remediations or [])
        ],
    }


@router.get(
    "/remediations",
    status_code=status.HTTP_200_OK,
    summary="List remediation actions",
    description="Returns all remediation actions performed across incidents.",
)
def list_remediations(
    db: Session = Depends(get_db),
    incident_id: Optional[uuid.UUID] = Query(default=None),
) -> List[Dict[str, Any]]:
    query = db.query(Remediation)
    if incident_id:
        query = query.filter(Remediation.incident_id == incident_id)
    remediations = query.order_by(Remediation.created_at.desc()).all()

    return [
        {
            "id": str(r.id),
            "incident_id": str(r.incident_id),
            "action_type": r.action_type,
            "description": r.description,
            "status": r.status,
            "rationale": r.rationale,
            "requested_by": r.requested_by,
            "approved_by": r.approved_by,
            "approved_at": r.approved_at.isoformat() if r.approved_at else None,
            "executed_at": r.executed_at.isoformat() if r.executed_at else None,
            "execution_output": r.execution_output,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in remediations
    ]
