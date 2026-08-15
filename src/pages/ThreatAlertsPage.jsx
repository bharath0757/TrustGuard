import React, { useState } from 'react';
import { 
  ShieldAlert, 
  ShieldCheck, 
  Search, 
  Clock, 
  FileText, 
  AlertTriangle,
  XCircle,
  CheckCircle2,
  Lock,
  ArrowRight
} from 'lucide-react';
import { PageContainer } from '../components/layout';
import { Card, Badge, Button, Input, Modal } from '../components/ui';
import { useTrustGuard } from '../hooks/useTrustGuard';

const SEVERITY_FILTERS = ['All', 'Critical', 'Warning', 'Resolved'];

export function ThreatAlertsPage() {
  const { threatAlerts, activeThreatCount } = useTrustGuard();
  const [searchQuery, setSearchQuery] = useState('');
  const [activeFilter, setActiveFilter] = useState('All');
  const [selectedAlert, setSelectedAlert] = useState(null);

  const blockedCount = threatAlerts.filter((a) => a.result === 'Access blocked' || a.result === 'Blocked' || a.result === 'Request denied').length;
  const resolvedCount = threatAlerts.filter((a) => a.severity === 'Resolved' || a.status === 'Resolved').length;

  const filteredAlerts = threatAlerts.filter((alert) => {
    const q = searchQuery.toLowerCase().trim();
    const matchesSearch =
      !q ||
      alert.title.toLowerCase().includes(q) ||
      alert.paper.toLowerCase().includes(q) ||
      alert.action.toLowerCase().includes(q) ||
      alert.result.toLowerCase().includes(q);

    let matchesFilter = true;
    if (activeFilter === 'Critical') {
      matchesFilter = alert.severity === 'Critical';
    } else if (activeFilter === 'Warning') {
      matchesFilter = alert.severity === 'Warning';
    } else if (activeFilter === 'Resolved') {
      matchesFilter = alert.severity === 'Resolved';
    }

    return matchesSearch && matchesFilter;
  });

  return (
    <PageContainer
      title="Threat Alerts"
      subtitle="Review security events and blocked access attempts."
    >
      {/* SECTION 4 — SUMMARY VALUES & FLOW BANNER */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        {/* Active alerts */}
        <Card className="p-4 bg-white border border-[#C7D0DA] shadow-xs">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-[#667085]">Active alerts</span>
            <AlertTriangle className="w-4 h-4 text-[#B7791F]" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-[#B7791F]">
              {activeThreatCount}
            </span>
            <span className="text-xs text-[#667085]">Requires Review</span>
          </div>
        </Card>

        {/* Blocked requests */}
        <Card className="p-4 bg-white border border-[#C7D0DA] shadow-xs">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-[#667085]">Blocked requests</span>
            <XCircle className="w-4 h-4 text-[#C44747]" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-[#C44747]">
              {blockedCount}
            </span>
            <span className="text-xs text-[#C44747] font-semibold">Access Prevented</span>
          </div>
        </Card>

        {/* Resolved */}
        <Card className="p-4 bg-white border border-[#C7D0DA] shadow-xs">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-[#667085]">Resolved</span>
            <CheckCircle2 className="w-4 h-4 text-[#2E7D5B]" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-[#2E7D5B]">
              {resolvedCount || 5}
            </span>
            <span className="text-xs text-[#667085]">Security Verified</span>
          </div>
        </Card>
      </div>

      {/* SECURITY FLOW BANNER */}
      <Card className="p-3.5 bg-white border border-[#C7D0DA] shadow-xs">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs">
          <span className="text-[#344054] font-bold uppercase text-[11px] tracking-wider">
            Security Enforcement Flow:
          </span>
          <div className="flex items-center gap-2 flex-wrap text-[#344054] font-medium">
            <span className="px-2 py-0.5 rounded bg-[#F1F4F7] border border-[#D5DDE5] text-[#344054]">
              Suspicious request
            </span>
            <ArrowRight className="w-3.5 h-3.5 text-[#98A2B3] shrink-0" />
            <span className="px-2 py-0.5 rounded bg-[#F1F4F7] border border-[#D5DDE5] text-[#344054]">
              Security check
            </span>
            <ArrowRight className="w-3.5 h-3.5 text-[#98A2B3] shrink-0" />
            <span className="px-2 py-0.5 rounded bg-[#FEF3F2] border border-[#FECDCA] text-[#C44747] font-semibold">
              Access blocked
            </span>
            <ArrowRight className="w-3.5 h-3.5 text-[#98A2B3] shrink-0" />
            <span className="px-2 py-0.5 rounded bg-[#ECFDF3] border border-[#D1FADF] text-[#2E7D5B] font-semibold">
              Event recorded
            </span>
          </div>
        </div>
      </Card>

      {/* TOP CONTROLS: SEARCH & SEVERITY FILTERS */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
        {/* Search input */}
        <div className="w-full md:w-80">
          <Input
            placeholder="Search alerts"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            icon={Search}
          />
        </div>

        {/* Severity filter buttons */}
        <div className="flex items-center gap-1.5 overflow-x-auto pb-1 md:pb-0">
          {SEVERITY_FILTERS.map((filter) => {
            const isActive = activeFilter === filter;
            return (
              <button
                key={filter}
                type="button"
                onClick={() => setActiveFilter(filter)}
                className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors cursor-pointer shrink-0 border ${
                  isActive
                    ? 'bg-[#17324D] text-white border-[#17324D] shadow-xs'
                    : 'bg-white text-[#475467] hover:text-[#17324D] hover:bg-[#F1F4F7] border-[#C7D0DA]'
                }`}
              >
                {filter}
              </button>
            );
          })}
        </div>
      </div>

      {/* SECTION 1 — ALERT LIST */}
      <div className="space-y-3">
        {filteredAlerts.map((alert) => {
          const isCritical = alert.severity === 'Critical';
          const isWarning = alert.severity === 'Warning';
          const isResolved = alert.severity === 'Resolved';

          return (
            <Card
              key={alert.id}
              className={`p-4 bg-white border border-[#C7D0DA] hover:border-[#AAB7C4] transition-colors cursor-pointer shadow-xs ${
                isCritical 
                  ? 'border-l-4 border-l-[#C44747]' 
                  : isWarning 
                  ? 'border-l-4 border-l-[#B7791F]' 
                  : 'border-l-4 border-l-[#2E7D5B]'
              }`}
              onClick={() => setSelectedAlert(alert)}
            >
              <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
                <div className="flex items-start gap-3">
                  <div className={`p-2 rounded-lg bg-[#F1F4F7] border border-[#D5DDE5] shrink-0 mt-0.5 ${
                    isCritical ? 'text-[#C44747]' : isWarning ? 'text-[#B7791F]' : 'text-[#2E7D5B]'
                  }`}>
                    {isCritical ? (
                      <ShieldAlert className="w-5 h-5" />
                    ) : isWarning ? (
                      <AlertTriangle className="w-5 h-5" />
                    ) : (
                      <CheckCircle2 className="w-5 h-5" />
                    )}
                  </div>

                  <div>
                    <div className="flex items-center gap-2 flex-wrap">
                      <h3 className="font-bold text-[#1F2933] text-sm sm:text-base">
                        {alert.title}
                      </h3>
                      <Badge
                        variant={isCritical ? 'danger' : isWarning ? 'warning' : 'success'}
                        size="sm"
                      >
                        {alert.severity}
                      </Badge>
                      <Badge
                        variant={isResolved ? 'success' : 'danger'}
                        size="sm"
                      >
                        {alert.result}
                      </Badge>
                    </div>

                    <div className="flex items-center gap-3 text-xs text-[#667085] mt-1.5 flex-wrap">
                      <span>Paper: <strong className="font-mono text-[#17324D]">{alert.paper}</strong></span>
                      <span>•</span>
                      <span>Action: <span className="text-[#344054] font-medium">{alert.action}</span></span>
                      <span>•</span>
                      <span className="flex items-center gap-1 font-mono text-[#667085]">
                        <Clock className="w-3.5 h-3.5 text-[#667085]" />
                        {alert.time}
                      </span>
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-2.5 self-end lg:self-center shrink-0">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={(e) => {
                      e.stopPropagation();
                      setSelectedAlert(alert);
                    }}
                  >
                    View Details
                  </Button>
                </div>
              </div>
            </Card>
          );
        })}

        {filteredAlerts.length === 0 && (
          <div className="p-10 text-center bg-white rounded-xl border border-[#C7D0DA] space-y-1.5 text-[#667085] text-xs shadow-xs">
            <ShieldCheck className="w-8 h-8 text-[#98A2B3] mx-auto" />
            <h3 className="text-sm font-bold text-[#1F2933]">No security alerts found</h3>
            <p>All monitored papers are currently within their expected security state.</p>
          </div>
        )}
      </div>

      {/* SECTION 2 & 3 — ALERT DETAILS & EVENT TIMELINE MODAL */}
      {selectedAlert && (
        <Modal
          isOpen={!!selectedAlert}
          onClose={() => setSelectedAlert(null)}
          title="Security Alert Details"
          subtitle={`Incident: ${selectedAlert.id}`}
          footer={
            <Button variant="secondary" size="sm" onClick={() => setSelectedAlert(null)}>
              Close
            </Button>
          }
        >
          <div className="space-y-4 text-xs">
            {/* SECTION 2 — ALERT DETAILS FIELDS */}
            <div className="p-3.5 rounded-lg bg-[#F1F4F7] border border-[#D5DDE5] space-y-2.5">
              <div className="flex justify-between items-center pb-2 border-b border-[#D5DDE5]">
                <span className="text-[#667085] font-medium">Incident:</span>
                <span className="font-bold text-[#1F2933] text-right">{selectedAlert.title}</span>
              </div>

              <div className="flex justify-between items-center">
                <span className="text-[#667085] font-medium">Paper:</span>
                <span className="font-mono text-[#17324D] font-bold">{selectedAlert.paper}</span>
              </div>

              <div className="flex justify-between items-center">
                <span className="text-[#667085] font-medium">Time:</span>
                <span className="font-mono text-[#1F2933]">{selectedAlert.time}</span>
              </div>

              <div className="flex justify-between items-center">
                <span className="text-[#667085] font-medium">Requested action:</span>
                <span className="text-[#1F2933] font-medium">{selectedAlert.action}</span>
              </div>

              <div className="flex justify-between items-center">
                <span className="text-[#667085] font-medium">Authorization:</span>
                <span className={`font-semibold ${selectedAlert.authorization === 'Failed' ? 'text-[#C44747]' : 'text-[#2E7D5B]'}`}>
                  {selectedAlert.authorization || 'Failed'}
                </span>
              </div>

              <div className="flex justify-between items-center">
                <span className="text-[#667085] font-medium">Decision:</span>
                <Badge variant={selectedAlert.decision === 'ACCESS BLOCKED' ? 'danger' : 'success'} size="sm">
                  {selectedAlert.decision}
                </Badge>
              </div>

              <div className="flex justify-between items-center">
                <span className="text-[#667085] font-medium">Status:</span>
                <span className="text-[#2E7D5B] font-semibold">{selectedAlert.decisionStatus || 'Recorded'}</span>
              </div>
            </div>

            {/* Reason Box */}
            <div className="p-3 rounded-lg bg-[#F1F4F7] border border-[#D5DDE5] space-y-1">
              <span className="text-[11px] font-bold text-[#344054] uppercase tracking-wider block">
                Decision Reason
              </span>
              <p className="text-[#344054] leading-relaxed">
                {selectedAlert.reason}
              </p>
            </div>

            {/* SECTION 3 — EVENT TIMELINE */}
            <div className="space-y-2">
              <span className="text-[11px] font-bold text-[#344054] uppercase tracking-wider block">
                Event Timeline
              </span>

              <div className="p-3 rounded-lg bg-[#F1F4F7] border border-[#D5DDE5] space-y-2">
                {(selectedAlert.timeline || []).map((step, idx) => (
                  <div
                    key={idx}
                    className="flex items-center justify-between text-xs py-1 border-b border-[#D5DDE5] last:border-none"
                  >
                    <div className="flex items-center gap-2">
                      <span className="w-1.5 h-1.5 rounded-full bg-[#C44747] shrink-0" />
                      <span className="text-[#1F2933] font-medium">{step.text}</span>
                    </div>
                    <span className="font-mono text-[#667085] text-[11px] shrink-0 ml-2">
                      {step.time}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </Modal>
      )}
    </PageContainer>
  );
}

// Re-export as AlertsPage for compatibility
export { ThreatAlertsPage as AlertsPage };
