import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { 
  Search, 
  Plus, 
  FileText, 
  CheckCircle2, 
  Clock, 
  Lock, 
  ArrowRight,
  ShieldCheck,
  RefreshCw
} from 'lucide-react';
import { PageContainer } from '../components/layout';
import { Card, Badge, Button, Input } from '../components/ui';
import { useTrustGuard } from '../hooks/useTrustGuard';

const STATUS_FILTERS = ['All', 'Protected', 'Pending', 'Authorized', 'Locked'];

export function PapersPage() {
  const navigate = useNavigate();
  const { papersList } = useTrustGuard();
  const [localPapers, setLocalPapers] = useState([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [activeFilter, setActiveFilter] = useState('All');
  const [isLoading, setIsLoading] = useState(false);

  // Combine shared state papersList with any newly created local demo papers
  const allPapers = [...localPapers, ...papersList];

  // Search and filter behavior
  const filteredPapers = allPapers.filter((paper) => {
    const q = searchQuery.toLowerCase().trim();
    const paperId = paper.id || paper.paperId;
    const matchesSearch =
      !q ||
      paperId.toLowerCase().includes(q) ||
      paper.examination.toLowerCase().includes(q);

    let matchesFilter = true;
    if (activeFilter === 'Protected') {
      matchesFilter = paper.securityStatus === 'Protected';
    } else if (activeFilter === 'Pending') {
      matchesFilter = paper.securityStatus === 'Pending';
    } else if (activeFilter === 'Authorized') {
      matchesFilter = paper.access === 'Authorized';
    } else if (activeFilter === 'Locked') {
      matchesFilter = paper.access === 'Locked';
    }

    return matchesSearch && matchesFilter;
  });

  // Create Demo Paper (frontend prototype state)
  const handleCreateDemoPaper = () => {
    setIsLoading(true);
    setTimeout(() => {
      const nextNum = allPapers.length + 1;
      const newPaper = {
        id: `DEMO-${String(nextNum).padStart(3, '0')}`,
        examination: `General Aptitude Examination #${nextNum}`,
        securityStatus: 'Protected',
        approvals: '0 / 3',
        access: 'Locked',
        lastUpdated: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      };
      setLocalPapers((prev) => [newPaper, ...prev]);
      setIsLoading(false);
    }, 200);
  };

  return (
    <PageContainer
      title="Question Papers"
      subtitle="Manage protected examination papers and monitor their security status."
      action={
        <Button
          variant="primary"
          size="sm"
          icon={Plus}
          onClick={handleCreateDemoPaper}
        >
          Create Demo Paper
        </Button>
      }
    >
      {/* TOP CONTROLS: Search and Status Filters */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
        {/* Search input */}
        <div className="w-full md:w-80">
          <Input
            placeholder="Search by paper ID or examination"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            icon={Search}
          />
        </div>

        {/* Status filter buttons */}
        <div className="flex items-center gap-1.5 overflow-x-auto pb-1 md:pb-0">
          {STATUS_FILTERS.map((filter) => {
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

      {/* PAPER LIST: Desktop Table / Responsive Mobile Cards */}
      {isLoading ? (
        <Card className="p-12 text-center bg-white border border-[#C7D0DA] text-[#667085] text-xs shadow-xs">
          <div className="flex items-center justify-center gap-2">
            <span className="w-4 h-4 border-2 border-[#17324D] border-t-transparent rounded-full animate-spin" />
            <span className="font-medium text-[#344054]">Loading question papers...</span>
          </div>
        </Card>
      ) : filteredPapers.length > 0 ? (
        <>
          {/* Desktop Table View */}
          <div className="hidden md:block overflow-hidden rounded-xl border border-[#C7D0DA] bg-white shadow-xs">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-[#D5DDE5] bg-[#F1F4F7] text-[#475467] font-semibold uppercase text-[11px] tracking-wider">
                  <th className="py-3.5 px-4">Paper ID</th>
                  <th className="py-3.5 px-4">Examination</th>
                  <th className="py-3.5 px-4">Security Status</th>
                  <th className="py-3.5 px-4">Approvals</th>
                  <th className="py-3.5 px-4">Access</th>
                  <th className="py-3.5 px-4">Last Updated</th>
                  <th className="py-3.5 px-4 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#D5DDE5] text-[#1F2933]">
                {filteredPapers.map((paper) => {
                  const paperId = paper.id || paper.paperId;
                  return (
                    <tr
                      key={paperId}
                      className="hover:bg-[#F1F4F7] transition-colors"
                    >
                      {/* Paper ID */}
                      <td className="py-3.5 px-4 font-mono font-bold text-[#17324D]">
                        {paperId}
                      </td>

                      {/* Examination */}
                      <td className="py-3.5 px-4 font-medium text-[#1F2933] max-w-xs truncate">
                        {paper.examination}
                      </td>

                      {/* Security Status */}
                      <td className="py-3.5 px-4">
                        {paper.securityStatus === 'Protected' ? (
                          <Badge variant="success" size="sm" dot>
                            Protected
                          </Badge>
                        ) : (
                          <Badge variant="warning" size="sm" dot>
                            Pending
                          </Badge>
                        )}
                      </td>

                      {/* Approvals */}
                      <td className="py-3.5 px-4 font-mono text-[#344054]">
                        {paper.approvals}
                      </td>

                      {/* Access */}
                      <td className="py-3.5 px-4">
                        {paper.access === 'Authorized' ? (
                          <Badge variant="success" size="sm">
                            Authorized
                          </Badge>
                        ) : (
                          <Badge variant="default" size="sm">
                            Locked
                          </Badge>
                        )}
                      </td>

                      {/* Last Updated */}
                      <td className="py-3.5 px-4 text-[#667085] font-mono">
                        {paper.lastUpdated}
                      </td>

                      {/* Action */}
                      <td className="py-3.5 px-4 text-right">
                        <Button
                          variant="secondary"
                          size="sm"
                          onClick={() => navigate(`/papers/${paperId}`)}
                        >
                          View Details
                        </Button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          {/* Mobile Card View */}
          <div className="block md:hidden space-y-3">
            {filteredPapers.map((paper) => {
              const paperId = paper.id || paper.paperId;
              return (
                <Card key={paperId} className="p-4 bg-white border border-[#C7D0DA] space-y-3 shadow-xs">
                  <div className="flex items-start justify-between gap-2">
                    <div>
                      <span className="font-mono text-xs font-bold text-[#17324D] block">
                        {paperId}
                      </span>
                      <h3 className="text-sm font-semibold text-[#1F2933] mt-0.5">
                        {paper.examination}
                      </h3>
                    </div>

                    {paper.securityStatus === 'Protected' ? (
                      <Badge variant="success" size="sm" dot>
                        Protected
                      </Badge>
                    ) : (
                      <Badge variant="warning" size="sm" dot>
                        Pending
                      </Badge>
                    )}
                  </div>

                  <div className="grid grid-cols-3 gap-2 p-2.5 rounded-lg bg-[#F1F4F7] border border-[#D5DDE5] text-xs">
                    <div>
                      <span className="text-[10px] text-[#667085] block font-medium">Approvals</span>
                      <span className="font-mono font-semibold text-[#1F2933]">{paper.approvals}</span>
                    </div>
                    <div>
                      <span className="text-[10px] text-[#667085] block font-medium">Access</span>
                      <span className={`font-semibold ${paper.access === 'Authorized' ? 'text-[#2E7D5B]' : 'text-[#667085]'}`}>
                        {paper.access}
                      </span>
                    </div>
                    <div>
                      <span className="text-[10px] text-[#667085] block font-medium">Updated</span>
                      <span className="font-mono text-[#667085]">{paper.lastUpdated}</span>
                    </div>
                  </div>

                  <Button
                    variant="secondary"
                    size="sm"
                    className="w-full justify-center"
                    onClick={() => navigate(`/papers/${paperId}`)}
                  >
                    View Details
                  </Button>
                </Card>
              );
            })}
          </div>
        </>
      ) : (
        /* Empty State */
        <div className="p-12 text-center bg-white rounded-xl border border-[#C7D0DA] space-y-2 shadow-xs">
          <FileText className="w-8 h-8 text-[#98A2B3] mx-auto" />
          <h3 className="text-sm font-bold text-[#1F2933]">No papers found</h3>
          <p className="text-xs text-[#667085]">Try changing your search or filter.</p>
        </div>
      )}
    </PageContainer>
  );
}
