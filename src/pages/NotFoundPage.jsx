import React from 'react';
import { Link } from 'react-router-dom';
import { ShieldAlert, ArrowLeft } from 'lucide-react';
import { PageContainer } from '../components/layout';
import { Card, Button } from '../components/ui';

export function NotFoundPage() {
  return (
    <PageContainer>
      <div className="min-h-[60vh] flex items-center justify-center">
        <Card className="p-8 max-w-md text-center space-y-4 border-[#E4E7EC] bg-white shadow-xs">
          <div className="w-14 h-14 rounded-xl bg-[#FEF3F2] border border-[#FECDCA] text-[#C44747] mx-auto flex items-center justify-center">
            <ShieldAlert className="w-7 h-7" />
          </div>
          <div className="space-y-1">
            <h2 className="text-xl font-bold text-[#17324D]">Page Not Found</h2>
            <p className="text-xs text-[#667085]">
              The requested section or resource record does not exist in TrustGuard.
            </p>
          </div>
          <Link to="/">
            <Button variant="primary" size="md" icon={ArrowLeft} className="w-full mt-4">
              Return to Security Dashboard
            </Button>
          </Link>
        </Card>
      </div>
    </PageContainer>
  );
}
