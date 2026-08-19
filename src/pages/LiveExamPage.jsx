import React from 'react';
import { useParams } from 'react-router-dom';
import { Monitor, Users, Clock, ShieldCheck } from 'lucide-react';
import { PageContainer } from '../components/layout';
import { Card, Badge } from '../components/ui';
import { useTrustGuard } from '../hooks/useTrustGuard';

export function LiveExamPage() {
  const { examId } = useParams();
  const { paper, auditEvents } = useTrustGuard();

  return (
    <PageContainer
      title="Live Exam Monitoring"
      description={`Real-time monitoring for exam ${examId || paper?.id || 'N/A'}`}
    >
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
        <Card className="p-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-green-100 rounded-lg flex items-center justify-center">
              <Monitor className="w-5 h-5 text-green-600" />
            </div>
            <div>
              <p className="text-xs text-slate-500">Exam Status</p>
              <p className="text-sm font-semibold text-slate-800">{paper?.examAccess || 'Pending'}</p>
            </div>
          </div>
        </Card>
        <Card className="p-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-blue-100 rounded-lg flex items-center justify-center">
              <Users className="w-5 h-5 text-blue-600" />
            </div>
            <div>
              <p className="text-xs text-slate-500">Active Students</p>
              <p className="text-sm font-semibold text-slate-800">–</p>
            </div>
          </div>
        </Card>
        <Card className="p-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-amber-100 rounded-lg flex items-center justify-center">
              <Clock className="w-5 h-5 text-amber-600" />
            </div>
            <div>
              <p className="text-xs text-slate-500">Time Remaining</p>
              <p className="text-sm font-semibold text-slate-800">–</p>
            </div>
          </div>
        </Card>
      </div>

      <Card className="p-6">
        <div className="flex items-center gap-2 mb-4">
          <ShieldCheck className="w-5 h-5 text-emerald-600" />
          <h3 className="text-sm font-semibold text-slate-800">Live Security Feed</h3>
        </div>
        <div className="space-y-2">
          {auditEvents && auditEvents.length > 0 ? (
            auditEvents.slice(0, 10).map((evt, i) => (
              <div key={evt.id || i} className="flex items-center gap-3 text-xs py-2 border-b border-slate-100 last:border-0">
                <Badge variant={evt.result === 'Blocked' ? 'destructive' : 'success'} size="sm">
                  {evt.result || 'OK'}
                </Badge>
                <span className="text-slate-500">{evt.time}</span>
                <span className="text-slate-700 font-medium">{evt.action}</span>
              </div>
            ))
          ) : (
            <p className="text-sm text-slate-400 text-center py-8">No live events yet</p>
          )}
        </div>
      </Card>
    </PageContainer>
  );
}
