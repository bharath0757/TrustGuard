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

  const blockedCount = 3;
  const recordedEventsCount = 6;

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
      matchesFilter = alert.severity === 'Resolved' || alert.severity === 'Info';
    }

    return matchesSearch && matchesFilter;
  });

  return (
    <PageContainer
      title="Threat Alerts"
      subtitle="Review security events and blocked access attempts."
    >
      {/* TOP SUMMARY — 3 Compact Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        {/* Active alerts */}
        <Card className="p-4 bg-white border border-[#C7D0DA] border-l-4 border-l-[#C44747] shadow-xs hover:-translate-y-0.5 transition-all duration-200">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-[#5E6B78]">Active alerts</span>
            <div className="w-7 h-7 rounded-lg bg-[#FDF2F2] border border-[#F2C2C2] flex items-center justify-center text-[#C44747]">
              <AlertTriangle className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-2.5 flex items-baseline justify-between">
            <span className="text-2xl font-bold text-[#C44747] tracking-tight">
              {activeThreatCount}
            </span>
            <span className="text-xs text-[#C44747] font-semibold bg-[#FDF2F2] px-2 py-0.5 rounded border border-[#F2C2C2]">
              Unresolved
            </span>
          </div>
        </Card>

        {/* Blocked requests */}
        <Card className="p-4 bg-white border border-[#C7D0DA] border-l-4 border-l-[#B7791F] shadow-xs hover:-translate-y-0.5 transition-all duration-200">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-[#5E6B78]">Blocked requests</span>
            <div className="w-7 h-7 rounded-lg bg-[#FAF3E7] border border-[#E8D4B5] flex items-center justify-center text-[#B7791F]">
              <XCircle className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-2.5 flex items-baseline justify-between">
            <span className="text-2xl font-bold text-[#B7791F] tracking-tight">
              {blockedCount}
            </span>
            <span className="text-xs text-[#B7791F] font-semibold bg-[#FAF3E7] px-2 py-0.5 rounded border border-[#E8D4B5]">
              Prevented
            </span>
          </div>
        </Card>

        {/* Recorded events */}
        <Card className="p-4 bg-white border border-[#C7D0DA] border-l-4 border-l-[#3E6B8C] shadow-xs hover:-translate-y-0.5 transition-all duration-200">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-[#5E6B78]">Recorded events</span>
            <div className="w-7 h-7 rounded-lg bg-[#EEF4F9] border border-[#C7D0DA] flex items-center justify-center text-[#3E6B8C]">
              <ShieldCheck className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-2.5 flex items-baseline justify-between">
            <span className="text-2xl font-bold text-[#17324D] tracking-tight">
              {recordedEventsCount}
            </span>
            <span className="text-xs text-[#3E6B8C] font-semibold bg-[#EEF4F9] px-2 py-0.5 rounded border border-[#C7D0DA]">
              Logged
            </span>
          </div>
        </Card>
      </div>

      {/* SEARCH & SEVERITY FILTER BAR */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 pt-1">
        <div className="w-full md:w-80">
          <Input
            placeholder="Search alerts by title or paper"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            icon={Search}
          />
        </div>

        <div className="flex items-center gap-1.5 overflow-x-auto pb-1 md:pb-0">
          {SEVERITY_FILTERS.map((filter) => {
            const isActive = activeFilter === filter;
            return (
              <button
                key={filter}
                type="button"
                onClick={() => setActiveFilter(filter)}
                className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer shrink-0 border ${
                  isActive
                    ? 'bg-[#17324D] text-white border-[#17324D] shadow-2xs'
                    : 'bg-white text-[#5E6B78] hover:text-[#182230] hover:bg-[#F0F4F8] border-[#C7D0DA]'
                }`}
              >
                {filter}
              </button>
            );
          })}
        </div>
      </div>

      {/* ALERT LIST ROWS */}
      <div className="space-y-3">
        {filteredAlerts.map((alert) => {
          const isCritical = alert.severity === 'Critical';
          const isWarning = alert.severity === 'Warning';
          const isBlocked = alert.result === 'Access blocked' || alert.result === 'Blocked' || alert.result === 'Request denied';

          return (
            <Card
              key={alert.id}
              className={`p-4 bg-white border border-[#C7D0DA] hover:-translate-y-0.5 transition-all duration-200 cursor-pointer shadow-xs ${
                isCritical 
                  ? 'border-l-4 border-l-[#C44747]' 
                  : isWarning 
                  ? 'border-l-4 border-l-[#B7791F]' 
                  : 'border-l-4 border-l-[#3E6B8C]'
              }`}
              onClick={() => setSelectedAlert(alert)}
            >
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                <div className="flex items-center gap-3">
                  <div className={`p-2 rounded-lg shrink-0 transition-colors ${
                    isCritical 
                      ? 'bg-[#FDF2F2] border border-[#F2C2C2] text-[#C44747]' 
                      : isWarning 
                      ? 'bg-[#FAF3E7] border border-[#E8D4B5] text-[#B7791F]' 
                      : 'bg-[#EEF4F9] border border-[#C7D0DA] text-[#3E6B8C]'
                  }`}>
                    {isCritical ? (
                      <ShieldAlert className="w-4 h-4" />
                    ) : isWarning ? (
                      <AlertTriangle className="w-4 h-4" />
                    ) : (
                      <CheckCircle2 className="w-4 h-4" />
                    )}
                  </div>

                  <div>
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className={`text-[10px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded border ${
                        isCritical 
                          ? 'bg-[#FDF2F2] text-[#C44747] border-[#F2C2C2]' 
                          : isWarning 
                          ? 'bg-[#FAF3E7] text-[#B7791F] border-[#E8D4B5]' 
                          : 'bg-[#EEF4F9] text-[#3E6B8C] border-[#C7D0DA]'
                      }`}>
                        {alert.severity}
                      </span>
                      <h3 className="font-bold text-[#182230] text-xs sm:text-sm">
                        {alert.title}
                      </h3>
                    </div>

                    <div className="flex items-center gap-2.5 text-xs text-[#5E6B78] mt-1 flex-wrap">
                      <span>Paper: <strong className="font-mono text-[#17324D]">{alert.paper}</strong></span>
                      <span>•</span>
                      <span className="flex items-center gap-1 font-mono">
                        <Clock className="w-3.5 h-3.5 text-[#5E6B78]" />
                        {alert.time}
                      </span>
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-3 self-end sm:self-center shrink-0">
                  <Badge
                    variant={isBlocked ? 'danger' : 'info'}
                    size="sm"
                    className="font-mono text-xs px-2 py-0.5"
                  >
                    [{isBlocked ? 'Blocked' : 'Recorded'}]
                  </Badge>

                  <Button
                    variant="outline"
                    size="sm"
                    onClick={(e) => {
                      e.stopPropagation();
                      setSelectedAlert(alert);
                    }}
                  >
                    Details
                  </Button>
                </div>
              </div>
            </Card>
          );
        })}

        {filteredAlerts.length === 0 && (
          <div className="p-8 text-center bg-white rounded-xl border border-[#C7D0DA] space-y-1 text-[#5E6B78] text-xs shadow-xs">
            <ShieldCheck className="w-7 h-7 text-[#5E6B78] mx-auto" />
            <h3 className="text-sm font-bold text-[#182230]">No security alerts found</h3>
            <p>All monitored papers are currently within their expected security state.</p>
          </div>
        )}
      </div>

      {/* ALERT DETAILS MODAL */}
      {selectedAlert && (
        <Modal
          isOpen={!!selectedAlert}
          onClose={() => setSelectedAlert(null)}
          title="Security Alert Details"
          subtitle={`Incident ID: ${selectedAlert.id}`}
          footer={
            <Button variant="secondary" size="sm" onClick={() => setSelectedAlert(null)}>
              Close
            </Button>
          }
        >
          <div className="space-y-4 text-xs">
            {/* ALERT DETAILS FIELDS */}
            <div className="p-3.5 rounded-lg bg-[#F0F4F8] border border-[#C7D0DA] space-y-2.5">
              <div className="flex justify-between items-center pb-2 border-b border-[#C7D0DA]">
                <span className="text-[#5E6B78] font-medium">Event:</span>
                <span className="font-bold text-[#182230] text-right">{selectedAlert.title}</span>
              </div>

              <div className="flex justify-between items-center">
                <span className="text-[#5E6B78] font-medium">Paper:</span>
                <span className="font-mono text-[#17324D] font-bold">{selectedAlert.paper}</span>
              </div>

              <div className="flex justify-between items-center">
                <span className="text-[#5E6B78] font-medium">Requested action:</span>
                <span className="text-[#182230] font-medium">{selectedAlert.action}</span>
              </div>

              <div className="flex justify-between items-center">
                <span className="text-[#5E6B78] font-medium">Authorization result:</span>
                <span className={`font-semibold ${selectedAlert.authorization === 'Failed' ? 'text-[#C44747]' : 'text-[#2E7D5B]'}`}>
                  {selectedAlert.authorization || 'Failed'}
                </span>
              </div>

              <div className="flex justify-between items-center">
                <span className="text-[#5E6B78] font-medium">Decision:</span>
                <Badge variant={selectedAlert.decision === 'ACCESS BLOCKED' ? 'danger' : 'success'} size="sm">
                  {selectedAlert.decision || 'ACCESS BLOCKED'}
                </Badge>
              </div>

              <div className="flex justify-between items-center">
                <span className="text-[#5E6B78] font-medium">Time:</span>
                <span className="font-mono text-[#182230]">{selectedAlert.time}</span>
              </div>
            </div>

            {/* Reason Box */}
            <div className="p-3 rounded-lg bg-[#F0F4F8] border border-[#C7D0DA] space-y-1">
              <span className="text-[11px] font-bold text-[#182230] uppercase tracking-wider block">
                Decision Reason
              </span>
              <p className="text-[#182230] leading-relaxed">
                {selectedAlert.reason}
              </p>
            </div>
          </div>
        </Modal>
      )}
    </PageContainer>
  );
}

// Re-export as AlertsPage for compatibility
export { ThreatAlertsPage as AlertsPage };

