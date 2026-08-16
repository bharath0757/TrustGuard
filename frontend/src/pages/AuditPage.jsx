import React, { useState } from 'react';
import { 
  History, 
  Search, 
  CheckCircle2, 
  XCircle, 
  Clock, 
  FileText, 
  User, 
  ShieldAlert, 
  Layers, 
  CheckSquare, 
  Calendar,
  List,
  GitCommit
} from 'lucide-react';
import { PageContainer } from '../components/layout';
import { Card, Badge, Button, Input, Modal } from '../components/ui';
import { useTrustGuard } from '../hooks/useTrustGuard';

const TYPE_FILTERS = ['All', 'Security', 'Approval', 'Paper', 'System'];
const RESULT_FILTERS = ['All', 'Success', 'Blocked'];

export function AuditPage() {
  const { auditEvents } = useTrustGuard();
  const [searchQuery, setSearchQuery] = useState('');
  const [typeFilter, setTypeFilter] = useState('All');
  const [resultFilter, setResultFilter] = useState('All');
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [viewMode, setViewMode] = useState('table'); // 'table' | 'timeline'

  const totalEventsCount = auditEvents.length;
  const successfulCount = auditEvents.filter((e) => e.result === 'Success').length;
  const blockedCount = auditEvents.filter((e) => e.result === 'Blocked').length;

  const filteredEvents = auditEvents.filter((evt) => {
    const q = searchQuery.toLowerCase().trim();
    const matchesSearch =
      !q ||
      evt.paper.toLowerCase().includes(q) ||
      evt.actor.toLowerCase().includes(q) ||
      evt.action.toLowerCase().includes(q) ||
      evt.type.toLowerCase().includes(q);

    const matchesType = typeFilter === 'All' || evt.type === typeFilter;
    const matchesResult = resultFilter === 'All' || evt.result === resultFilter;

    return matchesSearch && matchesType && matchesResult;
  });

  return (
    <PageContainer
      title="Audit Trail"
      subtitle="Review recorded actions and security events for protected examination papers."
    >
      {/* SECTION 4 — STATUS SUMMARY */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <Card className="p-4 bg-white border border-[#C7D0DA] shadow-xs">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-[#667085]">Total events</span>
            <History className="w-4 h-4 text-[#667085]" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-[#17324D]">
              {totalEventsCount}
            </span>
            <span className="text-xs text-[#667085]">Recorded Today</span>
          </div>
        </Card>

        <Card className="p-4 bg-white border border-[#C7D0DA] shadow-xs">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-[#667085]">Successful actions</span>
            <CheckCircle2 className="w-4 h-4 text-[#2E7D5B]" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-[#2E7D5B]">
              {successfulCount}
            </span>
            <span className="text-xs text-[#667085]">Authorized & Verified</span>
          </div>
        </Card>

        <Card className="p-4 bg-white border border-[#C7D0DA] shadow-xs">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-[#667085]">Blocked actions</span>
            <XCircle className="w-4 h-4 text-[#C44747]" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-[#C44747]">
              {blockedCount}
            </span>
            <span className="text-xs text-[#C44747] font-semibold">Access Intercepted</span>
          </div>
        </Card>
      </div>

      {/* TOP CONTROLS: SEARCH & FILTERS & VIEW TOGGLE */}
      <div className="space-y-3">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
          {/* Search input */}
          <div className="w-full md:w-80">
            <Input
              placeholder="Search by paper, actor or event"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              icon={Search}
            />
          </div>

          {/* View mode toggle */}
          <div className="flex items-center gap-1 bg-[#F1F4F7] p-1 rounded-lg border border-[#D5DDE5] self-start md:self-auto shadow-xs">
            <button
              type="button"
              onClick={() => setViewMode('table')}
              className={`px-3 py-1.5 rounded-md text-xs font-semibold transition-colors flex items-center gap-1.5 cursor-pointer ${
                viewMode === 'table'
                  ? 'bg-white text-[#17324D] shadow-xs border border-[#C7D0DA]'
                  : 'text-[#667085] hover:text-[#17324D]'
              }`}
            >
              <List className="w-3.5 h-3.5" />
              Event List
            </button>
            <button
              type="button"
              onClick={() => setViewMode('timeline')}
              className={`px-3 py-1.5 rounded-md text-xs font-semibold transition-colors flex items-center gap-1.5 cursor-pointer ${
                viewMode === 'timeline'
                  ? 'bg-white text-[#17324D] shadow-xs border border-[#C7D0DA]'
                  : 'text-[#667085] hover:text-[#17324D]'
              }`}
            >
              <GitCommit className="w-3.5 h-3.5" />
              Timeline View
            </button>
          </div>
        </div>

        {/* Filter bars */}
        {viewMode === 'table' && (
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pt-1">
            {/* Event Type Filters */}
            <div className="flex items-center gap-1.5 overflow-x-auto pb-1 sm:pb-0">
              <span className="text-xs text-[#667085] font-semibold mr-1 hidden lg:inline">
                Type:
              </span>
              {TYPE_FILTERS.map((filter) => {
                const isActive = typeFilter === filter;
                return (
                  <button
                    key={filter}
                    type="button"
                    onClick={() => setTypeFilter(filter)}
                    className={`px-2.5 py-1 rounded-md text-xs font-semibold transition-colors cursor-pointer shrink-0 border ${
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

            {/* Result Filters */}
            <div className="flex items-center gap-1.5 shrink-0">
              <span className="text-xs text-[#667085] font-semibold mr-1 hidden lg:inline">
                Result:
              </span>
              {RESULT_FILTERS.map((filter) => {
                const isActive = resultFilter === filter;
                return (
                  <button
                    key={filter}
                    type="button"
                    onClick={() => setResultFilter(filter)}
                    className={`px-2.5 py-1 rounded-md text-xs font-semibold transition-colors cursor-pointer border ${
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
        )}
      </div>

      {/* VIEW: TIMELINE VIEW (SECTION 3) */}
      {viewMode === 'timeline' ? (
        <Card
          className="p-5 bg-white border border-[#C7D0DA] space-y-4 shadow-xs"
          header={
            <div className="flex items-center justify-between w-full">
              <div className="flex items-center gap-2">
                <Clock className="w-4 h-4 text-[#17324D]" />
                <h3 className="text-sm font-bold text-[#17324D]">
                  Chronological Event Timeline
                </h3>
              </div>
              <span className="text-xs text-[#667085]">
                Live Audit Stream
              </span>
            </div>
          }
        >
          <div className="relative pl-6 space-y-6 before:absolute before:left-2.5 before:top-2 before:bottom-2 before:w-0.5 before:bg-[#D5DDE5]">
            {auditEvents.slice(0, 8).map((item, idx) => {
              const isBlocked = item.result === 'Blocked' || item.type === 'Security';
              return (
                <div key={idx} className="relative group">
                  {/* Timeline dot */}
                  <span className={`absolute -left-6 top-1.5 w-3 h-3 rounded-full border-2 border-white ${
                    isBlocked ? 'bg-[#C44747]' : 'bg-[#17324D]'
                  }`} />

                  <div className="p-3.5 rounded-lg bg-[#F1F4F7] border border-[#D5DDE5] flex items-center justify-between">
                    <div>
                      <span className="text-xs font-bold text-[#1F2933] block">
                        {item.action}
                      </span>
                      <span className="text-[11px] text-[#667085]">
                        Category: {item.type} • Paper: <span className="font-mono font-bold text-[#17324D]">{item.paper}</span> • Actor: {item.actor}
                      </span>
                    </div>

                    <span className="text-xs font-mono text-[#667085] shrink-0 ml-2">
                      {item.time}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        </Card>
      ) : (
        /* VIEW: TABLE VIEW (SECTION 1) */
        <>
          {filteredEvents.length > 0 ? (
            <>
              {/* Desktop Table View */}
              <div className="hidden md:block overflow-hidden rounded-xl border border-[#C7D0DA] bg-white shadow-xs">
                <table className="w-full text-left border-collapse text-xs">
                  <thead>
                    <tr className="border-b border-[#D5DDE5] bg-[#F1F4F7] text-[#475467] font-semibold uppercase text-[11px] tracking-wider">
                      <th className="py-3.5 px-4">Time</th>
                      <th className="py-3.5 px-4">Event Type</th>
                      <th className="py-3.5 px-4">Actor</th>
                      <th className="py-3.5 px-4">Paper</th>
                      <th className="py-3.5 px-4">Action</th>
                      <th className="py-3.5 px-4">Result</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#D5DDE5] text-[#1F2933]">
                    {filteredEvents.map((evt) => {
                      const isBlocked = evt.result === 'Blocked';

                      return (
                        <tr
                          key={evt.id}
                          onClick={() => setSelectedEvent(evt)}
                          className={`hover:bg-[#F1F4F7] transition-colors cursor-pointer ${
                            isBlocked ? 'bg-[#FEF3F2]/40' : ''
                          }`}
                        >
                          {/* Time */}
                          <td className="py-3 px-4 font-mono text-[#667085] whitespace-nowrap">
                            {evt.time}
                          </td>

                          {/* Event Type */}
                          <td className="py-3 px-4">
                            <span className="px-2 py-0.5 rounded bg-[#F1F4F7] border border-[#D5DDE5] text-[11px] font-semibold text-[#344054]">
                              {evt.type}
                            </span>
                          </td>

                          {/* Actor */}
                          <td className="py-3 px-4 font-medium text-[#1F2933]">
                            {evt.actor}
                          </td>

                          {/* Paper */}
                          <td className="py-3 px-4 font-mono font-bold text-[#17324D]">
                            {evt.paper}
                          </td>

                          {/* Action */}
                          <td className="py-3 px-4 font-medium text-[#1F2933] max-w-xs truncate">
                            {evt.action}
                          </td>

                          {/* Result */}
                          <td className="py-3 px-4">
                            {isBlocked ? (
                              <Badge variant="danger" size="sm">
                                Blocked
                              </Badge>
                            ) : (
                              <Badge variant="success" size="sm">
                                Success
                              </Badge>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>

              {/* Mobile Card View */}
              <div className="block md:hidden space-y-3">
                {filteredEvents.map((evt) => {
                  const isBlocked = evt.result === 'Blocked';

                  return (
                    <Card
                      key={evt.id}
                      className={`p-4 bg-white border border-[#C7D0DA] space-y-2 cursor-pointer shadow-xs ${
                        isBlocked ? 'border-l-4 border-l-[#C44747]' : ''
                      }`}
                      onClick={() => setSelectedEvent(evt)}
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-mono text-xs text-[#667085]">
                          {evt.time}
                        </span>
                        {isBlocked ? (
                          <Badge variant="danger" size="sm">Blocked</Badge>
                        ) : (
                          <Badge variant="success" size="sm">Success</Badge>
                        )}
                      </div>

                      <div>
                        <h4 className="text-sm font-bold text-[#1F2933]">
                          {evt.action}
                        </h4>
                        <div className="flex items-center gap-2 text-xs text-[#667085] mt-1">
                          <span>Actor: <strong className="text-[#1F2933]">{evt.actor}</strong></span>
                          <span>•</span>
                          <span>Paper: <strong className="font-mono text-[#17324D]">{evt.paper}</strong></span>
                        </div>
                      </div>
                    </Card>
                  );
                })}
              </div>
            </>
          ) : (
            <div className="p-10 text-center bg-white rounded-xl border border-[#C7D0DA] space-y-1.5 text-[#667085] text-xs shadow-xs">
              <History className="w-8 h-8 text-[#98A2B3] mx-auto" />
              <h3 className="text-sm font-bold text-[#1F2933]">No audit events found</h3>
              <p>Try adjusting your search query or filter parameters.</p>
            </div>
          )}
        </>
      )}

      {/* SECTION 2 — EVENT DETAILS MODAL */}
      {selectedEvent && (
        <Modal
          isOpen={!!selectedEvent}
          onClose={() => setSelectedEvent(null)}
          title="Audit Event Details"
          subtitle={`Event ID: ${selectedEvent.id}`}
          footer={
            <Button variant="secondary" size="sm" onClick={() => setSelectedEvent(null)}>
              Close
            </Button>
          }
        >
          <div className="space-y-4 text-xs">
            <div className="p-3.5 rounded-lg bg-[#F1F4F7] border border-[#D5DDE5] space-y-2.5">
              <div className="flex justify-between items-center pb-2 border-b border-[#D5DDE5]">
                <span className="text-[#667085] font-medium">Timestamp:</span>
                <span className="font-mono text-[#1F2933] font-bold">{selectedEvent.time}</span>
              </div>

              <div className="flex justify-between items-center">
                <span className="text-[#667085] font-medium">Event type:</span>
                <span className="font-medium text-[#1F2933]">{selectedEvent.type}</span>
              </div>

              <div className="flex justify-between items-center">
                <span className="text-[#667085] font-medium">Actor:</span>
                <span className="font-semibold text-[#1F2933]">{selectedEvent.actor}</span>
              </div>

              <div className="flex justify-between items-center">
                <span className="text-[#667085] font-medium">Paper ID:</span>
                <span className="font-mono text-[#17324D] font-bold">{selectedEvent.paper}</span>
              </div>

              <div className="flex justify-between items-center">
                <span className="text-[#667085] font-medium">Action:</span>
                <span className="text-[#1F2933] font-medium">{selectedEvent.requestedAction || selectedEvent.action}</span>
              </div>

              <div className="flex justify-between items-center">
                <span className="text-[#667085] font-medium">Result:</span>
                <Badge variant={selectedEvent.result === 'Blocked' ? 'danger' : 'success'} size="sm">
                  {selectedEvent.result}
                </Badge>
              </div>
            </div>

            <div>
              <span className="text-[11px] font-bold text-[#344054] uppercase tracking-wider block mb-1">
                Description
              </span>
              <p className="text-[#344054] bg-[#F1F4F7] p-3 rounded-lg border border-[#D5DDE5] leading-relaxed">
                {selectedEvent.description}
              </p>
            </div>
          </div>
        </Modal>
      )}
    </PageContainer>
  );
}
