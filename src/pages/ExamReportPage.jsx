import React from 'react';
import { useParams, Link } from 'react-router-dom';
import { FileText, ShieldCheck, CheckCircle2, AlertTriangle, ArrowLeft } from 'lucide-react';
import { PageContainer } from '../components/layout';
import { Card, Badge } from '../components/ui';
import { useTrustGuard } from '../hooks/useTrustGuard';

export function ExamReportPage() {
  const { examId } = useParams();
  const { paper, auditEvents, threatAlerts, officers } = useTrustGuard();

  const blockedCount = threatAlerts?.filter(a => a.result === 'Access blocked').length || 0;
  const approvedCount = Object.values(officers || {}).filter(o => o.status === 'Approved').length;

  return (
    <PageContainer
      title="Exam Security Report"
      description={`Post-exam security report for ${examId || paper?.id || 'N/A'}`}
    >
      <Link to="/" className="inline-flex items-center gap-1.5 text-sm text-blue-600 hover:text-blue-700 mb-4">
        <ArrowLeft className="w-4 h-4" /> Back to Dashboard
      </Link>

      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
        <Card className="p-4">
          <div className="flex items-center gap-3">
            <FileText className="w-5 h-5 text-blue-600" />
            <div>
              <p className="text-xs text-slate-500">Exam</p>
              <p className="text-sm font-semibold text-slate-800">{paper?.id || examId || '–'}</p>
            </div>
          </div>
        </Card>
        <Card className="p-4">
          <div className="flex items-center gap-3">
            <ShieldCheck className="w-5 h-5 text-emerald-600" />
            <div>
              <p className="text-xs text-slate-500">Guardian Approvals</p>
              <p className="text-sm font-semibold text-slate-800">{approvedCount} / {paper?.requiredApprovals || 3}</p>
            </div>
          </div>
        </Card>
        <Card className="p-4">
          <div className="flex items-center gap-3">
            <AlertTriangle className="w-5 h-5 text-red-500" />
            <div>
              <p className="text-xs text-slate-500">Threats Blocked</p>
              <p className="text-sm font-semibold text-slate-800">{blockedCount}</p>
            </div>
          </div>
        </Card>
        <Card className="p-4">
          <div className="flex items-center gap-3">
            <CheckCircle2 className="w-5 h-5 text-green-600" />
            <div>
              <p className="text-xs text-slate-500">Audit Events</p>
              <p className="text-sm font-semibold text-slate-800">{auditEvents?.length || 0}</p>
            </div>
          </div>
        </Card>
      </div>

      {/* Audit Trail */}
      <Card className="p-6">
        <h3 className="text-sm font-semibold text-slate-800 mb-4">Audit Trail</h3>
        <div className="space-y-2">
          {auditEvents && auditEvents.length > 0 ? (
            auditEvents.map((evt, i) => (
              <div key={evt.id || i} className="flex items-center gap-3 text-xs py-2 border-b border-slate-100 last:border-0">
                <Badge variant={evt.result === 'Blocked' ? 'destructive' : 'default'} size="sm">
                  {evt.type || 'Event'}
                </Badge>
                <span className="text-slate-500 font-mono">{evt.time}</span>
                <span className="text-slate-700">{evt.action}</span>
                <span className="ml-auto text-slate-400">{evt.actor}</span>
              </div>
            ))
          ) : (
            <p className="text-sm text-slate-400 text-center py-8">No audit events recorded</p>
          )}
        </div>
      </Card>
    </PageContainer>
  );
}
