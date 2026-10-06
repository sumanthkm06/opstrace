from pydantic import BaseModel
from typing import List, Optional
import uuid
from datetime import datetime

class DependencyNode(BaseModel):
    service_id: uuid.UUID
    service_name: str
    host_id: uuid.UUID
    host_name: str
    criticality: str
    dependency_type: str
    depth: int

class DependencyImpactAnalysis(BaseModel):
    service_id: uuid.UUID
    service_name: str
    downstream_impacts: List[DependencyNode]  # Services that depend on this one
    upstream_dependencies: List[DependencyNode]  # Services this one depends on
