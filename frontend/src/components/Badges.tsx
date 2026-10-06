/** Badge helpers — derive CSS class from a value string */

function badge(cls: string, text: string) {
  return <span className={`badge badge-${cls}`}>{text}</span>
}

export function StatusBadge({ status }: { status: string }) {
  return badge(status.toLowerCase(), status)
}

export function SeverityBadge({ severity }: { severity: string }) {
  return badge(`sev-${severity.toLowerCase()}`, severity.toUpperCase())
}

export function IncidentStatusBadge({ status }: { status: string }) {
  return badge(status.toLowerCase(), status)
}
