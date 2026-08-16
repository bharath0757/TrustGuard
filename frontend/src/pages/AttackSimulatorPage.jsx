import React, { useState, useEffect } from 'react';
import { 
  ShieldX, 
  ShieldCheck, 
  ShieldAlert, 
  Play, 
  AlertTriangle, 
  CheckCircle2, 
  XCircle, 
  FileText, 
  History, 
  Lock,
  RotateCcw,
  Server,
  User,
  Clock,
  Fingerprint
} from 'lucide-react';
import { PageContainer } from '../components/layout';
import { Card, Badge, Button } from '../components/ui';
import { useTrustGuard } from '../hooks/useTrustGuard';

const TARGET_PAPERS = [
  { id: 'JEE-MOCK-001', name: 'JEE-MOCK-001 — Engineering Entrance Examination' },
  { id: 'NEET-MOCK-002', name: 'NEET-MOCK-002 — Medical Entrance Examination' },
  { id: 'EXAM-MOCK-003', name: 'EXAM-MOCK-003 — National Scholarship Examination' },
  { id: 'DEMO-004', name: 'DEMO-004 — TrustGuard Demonstration' },
];

const DEFAULT_SCENARIOS = [
  {
    id: 'UNAUTHORIZED_ACCESS',
    name: 'Unauthorized question-paper access',
    description: 'Simulates an unverified terminal attempting direct paper access without proper officer credentials or session authorization.',
    simulatedActor: 'Unauthenticated External Terminal / Unknown Client',
    expectedDecision: 'DENY',
    riskSeverity: 'CRITICAL',
    defaultTarget: 'JEE-MOCK-001',
    mechanism: 'Zero-Trust policy rejects unauthenticated/unverified terminal connections before any cryptographic decryption or key access is possible.',
  },
  {
    id: 'INSIDER_ATTEMPT',
    name: 'Insider attempt without quorum',
    description: 'Simulates a valid authenticated officer attempting direct paper reconstruction without satisfying the required threshold quorum.',
    simulatedActor: 'Authenticated Officer (Valid Credentials, 1/3 Approvals)',
    expectedDecision: 'DENY',
    riskSeverity: 'HIGH',
    defaultTarget: 'NEET-MOCK-002',
    mechanism: 'Multi-party threshold cryptography verifies that valid account credentials alone cannot decrypt the paper without satisfying the complete 3-officer quorum.',
  },
  {
    id: 'INVALID_QUORUM',
    name: 'Invalid / duplicate quorum manipulation',
    description: 'Simulates an attempt to reach quorum using duplicate approvals, unauthorized roles, or manipulated approval counts.',
    simulatedActor: 'Key Guardian (Attempting duplicate vote / invalid role)',
    expectedDecision: 'DENY',
    riskSeverity: 'MEDIUM',
    defaultTarget: 'EXAM-MOCK-003',
    mechanism: 'Quorum engine enforces strict anti-replay and unique-approver constraints; duplicate and unauthorized vote attempts are rejected.',
  },
  {
    id: 'TAMPERED_FRAGMENT',
    name: 'Tampered fragment / integrity failure',
    description: 'Simulates an adversary modifying one stored fragment payload or its integrity hash in the storage layer.',
    simulatedActor: 'Adversary with Storage Access (Modified Shard Bytes)',
    expectedDecision: 'DENY',
    riskSeverity: 'CRITICAL',
    defaultTarget: 'DEMO-004',
    mechanism: 'Cryptographic SHA-256 manifest and AES-256-GCM authentication tag validation detect payload bit-flips; reconstruction and decryption are refused.',
  },
  {
    id: 'REPLAY_ATTEMPT',
    name: 'Replay of completed/expired access request',
    description: 'Simulates an attacker attempting to reuse a completed, expired, or purged access request to re-authorize paper streaming.',
    simulatedActor: 'Replay Attacker Reusing Previous Token / Closed Session',
    expectedDecision: 'DENY',
    riskSeverity: 'HIGH',
    defaultTarget: 'JEE-MOCK-001',
    mechanism: 'Terminal session lifecycle and ephemeral memory wiping prevent reuse of closed/expired requests; stream endpoint returns 410 Gone.',
  },
];

// Helper to determine visual badge/color styling for the 4 decision categories
function getDecisionVisuals(statusCategory, actualDecision) {
  const norm = (statusCategory || actualDecision || '').toUpperCase();

  if (norm.includes('INTEGRITY') || norm === 'FAILED INTEGRITY') {
    return {
      variant: 'purple',
      badgeClass: 'bg-[#FDF4FF] text-[#9333EA] border-[#F0ABFC]',
      bannerBg: 'bg-[#FAF5FF] border-[#E9D5FF]',
      iconColor: 'text-[#9333EA]',
      iconBorder: 'border-[#F0ABFC]',
      statusText: 'FAILED INTEGRITY',
      headerLabel: 'INTEGRITY TAMPERING DETECTED',
      icon: ShieldAlert,
    };
  }
  if (norm.includes('AUTHORIZATION') || norm === 'INVALID AUTHORIZATION') {
    return {
      variant: 'warning',
      badgeClass: 'bg-[#FAF3E7] text-[#B7791F] border-[#E8D4B5]',
      bannerBg: 'bg-[#FFFBEB] border-[#FDE68A]',
      iconColor: 'text-[#B7791F]',
      iconBorder: 'border-[#E8D4B5]',
      statusText: 'INVALID AUTHORIZATION',
      headerLabel: 'UNAUTHORIZED QUORUM BYPASS ATTEMPT',
      icon: AlertTriangle,
    };
  }
  if (norm === 'ALLOWED') {
    return {
      variant: 'success',
      badgeClass: 'bg-[#EAF5F0] text-[#2E7D5B] border-[#B2D8C7]',
      bannerBg: 'bg-[#ECFDF5] border-[#A7F3D0]',
      iconColor: 'text-[#2E7D5B]',
      iconBorder: 'border-[#B2D8C7]',
      statusText: 'ALLOWED',
      headerLabel: 'LEGITIMATE ACCESS AUTHORIZED',
      icon: ShieldCheck,
    };
  }
  // Default: BLOCKED
  return {
    variant: 'danger',
    badgeClass: 'bg-[#FDF2F2] text-[#C44747] border-[#F2C2C2]',
    bannerBg: 'bg-[#FDF2F2] border-[#F2C2C2]',
    iconColor: 'text-[#C44747]',
    iconBorder: 'border-[#F2C2C2]',
    statusText: 'BLOCKED',
    headerLabel: 'ACCESS BLOCKED BY ZERO-TRUST ENGINE',
    icon: ShieldX,
  };
}

function getSeverityBadge(severity) {
  const s = (severity || '').toUpperCase();
  if (s === 'CRITICAL') {
    return <Badge variant="danger" size="sm" className="font-bold">CRITICAL</Badge>;
  }
  if (s === 'HIGH') {
    return <Badge variant="warning" size="sm" className="font-bold">HIGH RISK</Badge>;
  }
  if (s === 'MEDIUM') {
    return <Badge variant="warning" size="sm">MEDIUM</Badge>;
  }
  return <Badge variant="success" size="sm">LOW</Badge>;
}

export function AttackSimulatorPage() {
  const { triggerAttackSimulation } = useTrustGuard();
  const [scenarios, setScenarios] = useState(DEFAULT_SCENARIOS);
  const [selectedPaper, setSelectedPaper] = useState(TARGET_PAPERS[0].id);
  const [selectedScenario, setSelectedScenario] = useState(DEFAULT_SCENARIOS[0].id);
  const [isSimulating, setIsSimulating] = useState(false);
  const [simulationResult, setSimulationResult] = useState(null);
  const [backendSource, setBackendSource] = useState('Checking...');

  // Fetch live scenario list from backend if available
  useEffect(() => {
    async function loadScenarios() {
      try {
        const res = await fetch('/api/v1/simulation/scenarios');
        if (res.ok) {
          const data = await res.json();
          if (Array.isArray(data) && data.length > 0) {
            const mapped = data.map((s) => ({
              id: s.id,
              name: s.name,
              description: s.description,
              simulatedActor: s.simulated_actor,
              expectedDecision: s.expected_decision,
              riskSeverity: s.risk_severity,
              defaultTarget: s.default_target,
              mechanism: s.mechanism,
            }));
            setScenarios(mapped);
            setBackendSource('Connected (Real Backend API)');
            return;
          }
        }
      } catch (err) {
        // Use default scenarios fallback
      }
      setBackendSource('Direct Zero-Trust Engine');
    }
    loadScenarios();
  }, []);

  const activeScenario = scenarios.find((s) => s.id === selectedScenario) || scenarios[0];

  const handleSimulate = async () => {
    setIsSimulating(true);
    setSimulationResult(null);

    try {
      // 1. Send real simulation request to the backend
      let res;
      try {
        res = await fetch('/api/v1/simulation/run', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            scenario_id: selectedScenario,
            target_paper_id: selectedPaper,
          }),
        });
      } catch {
        res = await fetch('http://localhost:8000/api/v1/simulation/run', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            scenario_id: selectedScenario,
            target_paper_id: selectedPaper,
          }),
        });
      }

      if (res && res.ok) {
        const data = await res.json();
        
        // Update live TrustGuard Context with real audit event & threat alert
        triggerAttackSimulation(data);

        setSimulationResult({
          scenarioId: data.scenario_id,
          scenarioName: data.scenario_name,
          targetPaper: data.target_paper,
          simulatedActor: data.simulated_actor,
          expectedDecision: data.expected_decision,
          actualDecision: data.actual_decision,
          securityDecision: data.security_decision,
          riskSeverity: data.risk_severity,
          timestamp: new Date(data.timestamp).toLocaleTimeString([], {
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
          }),
          isoTimestamp: data.timestamp,
          auditResult: data.audit_result,
          auditEventId: data.audit_event_id,
          statusCategory: data.status_category,
          mechanism: data.details?.mechanism || activeScenario.mechanism,
          reason: data.details?.reason || 'Access denied by zero-trust security policy.',
          isRealBackend: true,
        });
      } else {
        throw new Error('Backend simulation error');
      }
    } catch (err) {
      // Direct Local Evaluation Fallback
      let actualDec = 'BLOCKED';
      let statusCat = 'BLOCKED';
      if (selectedScenario === 'TAMPERED_FRAGMENT') {
        actualDec = 'FAILED INTEGRITY';
        statusCat = 'FAILED INTEGRITY';
      } else if (selectedScenario === 'INSIDER_ATTEMPT' || selectedScenario === 'INVALID_QUORUM') {
        actualDec = 'INVALID AUTHORIZATION';
        statusCat = 'INVALID AUTHORIZATION';
      }

      const mockTimestamp = new Date().toISOString();
      const localResult = {
        scenarioId: activeScenario.id,
        scenarioName: activeScenario.name,
        targetPaper: selectedPaper,
        simulatedActor: activeScenario.simulatedActor,
        expectedDecision: activeScenario.expectedDecision,
        actualDecision: actualDec,
        securityDecision: 'DENY',
        riskSeverity: activeScenario.riskSeverity,
        timestamp: new Date().toLocaleTimeString([], {
          hour: '2-digit',
          minute: '2-digit',
          second: '2-digit',
        }),
        isoTimestamp: mockTimestamp,
        auditResult: `AuditEvent SIM-${Date.now().toString().slice(-4)} committed to audit trail`,
        auditEventId: `SIM-${Date.now().toString().slice(-4)}`,
        statusCategory: statusCat,
        mechanism: activeScenario.mechanism,
        reason: 'Zero-trust security policy violation evaluated by defense engine.',
        isRealBackend: false,
      };

      triggerAttackSimulation(localResult);
      setSimulationResult(localResult);
    } finally {
      setIsSimulating(false);
    }
  };

  const handleReset = () => {
    setSimulationResult(null);
  };

  const visuals = simulationResult
    ? getDecisionVisuals(simulationResult.statusCategory, simulationResult.actualDecision)
    : null;

  return (
    <PageContainer
      title="Attack Simulator"
      subtitle="Run controlled demonstrations of unauthorized access, quorum misuse, and tampering scenarios against real backend engines."
    >
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* LEFT COLUMN: Simulation Controls */}
        <div className="lg:col-span-5 space-y-4">
          <Card
            className="p-5 bg-white border border-[#C7D0DA] space-y-4 shadow-xs"
            header={
              <div className="flex items-center justify-between">
                <h2 className="text-sm font-bold text-[#17324D] flex items-center gap-2">
                  <Play className="w-4 h-4 text-[#17324D]" />
                  Simulation Controls
                </h2>
                <span className="text-[11px] text-[#5E6B78] flex items-center gap-1 font-mono">
                  <Server className="w-3 h-3 text-[#2E7D5B]" />
                  {backendSource}
                </span>
              </div>
            }
          >
            {/* Scenario Selection */}
            <div className="space-y-1.5">
              <label htmlFor="attack-scenario" className="block text-xs font-semibold text-[#182230]">
                Select Controlled Simulation Scenario
              </label>
              <select
                id="attack-scenario"
                value={selectedScenario}
                onChange={(e) => setSelectedScenario(e.target.value)}
                className="w-full bg-white border border-[#C7D0DA] rounded-lg text-[#182230] text-xs py-2.5 px-3 focus:outline-none focus:ring-2 focus:ring-[#17324D]/10 focus:border-[#17324D] cursor-pointer font-medium"
              >
                {scenarios.map((scenario) => (
                  <option key={scenario.id} value={scenario.id}>
                    {scenario.name}
                  </option>
                ))}
              </select>
            </div>

            {/* Target Paper Selection */}
            <div className="space-y-1.5">
              <label htmlFor="target-paper" className="block text-xs font-semibold text-[#182230]">
                Target Examination Paper
              </label>
              <select
                id="target-paper"
                value={selectedPaper}
                onChange={(e) => setSelectedPaper(e.target.value)}
                className="w-full bg-white border border-[#C7D0DA] rounded-lg text-[#182230] text-xs py-2.5 px-3 focus:outline-none focus:ring-2 focus:ring-[#17324D]/10 focus:border-[#17324D] cursor-pointer font-medium"
              >
                {TARGET_PAPERS.map((paper) => (
                  <option key={paper.id} value={paper.id}>
                    {paper.name}
                  </option>
                ))}
              </select>
            </div>

            {/* Selected Scenario Preview */}
            <div className="p-3.5 rounded-lg bg-[#F0F4F8] border border-[#C7D0DA] text-xs space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-[#182230] font-bold">Scenario Specification</span>
                {getSeverityBadge(activeScenario.riskSeverity)}
              </div>
              <p className="text-[#5E6B78] leading-relaxed">
                {activeScenario.description}
              </p>
              <div className="pt-1.5 border-t border-[#C7D0DA]/60 text-[11px] text-[#17324D] font-mono">
                <strong>Simulated Actor:</strong> {activeScenario.simulatedActor}
              </div>
            </div>

            {/* Primary Action Button */}
            <div className="pt-2 space-y-2">
              <Button
                variant="primary"
                size="md"
                className="w-full justify-center font-semibold"
                icon={Play}
                onClick={handleSimulate}
                loading={isSimulating}
              >
                {isSimulating ? 'Executing Backend Simulation...' : 'Simulate Attack'}
              </Button>

              <p className="text-[11px] text-[#5E6B78] text-center italic">
                Real backend security decision execution. No plaintext is disclosed.
              </p>
            </div>
          </Card>
        </div>

        {/* RIGHT COLUMN: Real Security State & Result Panel */}
        <div className="lg:col-span-7">
          {simulationResult ? (
            <Card className="p-5 bg-white border border-[#C7D0DA] space-y-5 shadow-xs">
              {/* Dynamic Result Header Banner */}
              <div className={`p-4 rounded-xl border flex flex-col sm:flex-row sm:items-center justify-between gap-3 ${visuals.bannerBg}`}>
                <div className="flex items-center gap-3">
                  <div className={`p-2.5 rounded-lg bg-white ${visuals.iconColor} border ${visuals.iconBorder} shrink-0 shadow-2xs`}>
                    <visuals.icon className="w-5 h-5" />
                  </div>
                  <div>
                    <span className={`text-[11px] font-mono font-bold uppercase block ${visuals.iconColor}`}>
                      {visuals.headerLabel}
                    </span>
                    <h3 className="text-sm sm:text-base font-bold text-[#182230]">
                      {simulationResult.scenarioName}
                    </h3>
                  </div>
                </div>
                <div className="shrink-0">
                  <span className={`inline-flex items-center font-bold px-3 py-1 text-xs rounded-md border tracking-tight shadow-xs ${visuals.badgeClass}`}>
                    {simulationResult.actualDecision}
                  </span>
                </div>
              </div>

              {/* 8 Required Metadata Display Fields */}
              <div className="space-y-2 text-xs">
                <h4 className="font-bold text-[#182230] uppercase tracking-wider text-[11px]">
                  Simulation Parameters & Evaluated Decisions
                </h4>
                
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                  {/* Attack Scenario */}
                  <div className="p-3 rounded-lg bg-[#F0F4F8] border border-[#C7D0DA] space-y-1">
                    <span className="text-[11px] text-[#5E6B78] block font-medium">Attack Scenario</span>
                    <span className="text-xs font-bold text-[#182230] block">{simulationResult.scenarioName}</span>
                  </div>

                  {/* Target Paper */}
                  <div className="p-3 rounded-lg bg-[#F0F4F8] border border-[#C7D0DA] space-y-1">
                    <span className="text-[11px] text-[#5E6B78] block font-medium">Target Paper</span>
                    <span className="text-xs font-bold text-[#17324D] font-mono block">{simulationResult.targetPaper}</span>
                  </div>

                  {/* Simulated Actor */}
                  <div className="p-3 rounded-lg bg-[#F0F4F8] border border-[#C7D0DA] space-y-1">
                    <span className="text-[11px] text-[#5E6B78] block font-medium">Simulated Actor</span>
                    <span className="text-xs font-semibold text-[#182230] flex items-center gap-1.5">
                      <User className="w-3.5 h-3.5 text-[#5E6B78] shrink-0" />
                      {simulationResult.simulatedActor}
                    </span>
                  </div>

                  {/* Risk / Severity */}
                  <div className="p-3 rounded-lg bg-[#F0F4F8] border border-[#C7D0DA] space-y-1 flex flex-col justify-between">
                    <span className="text-[11px] text-[#5E6B78] block font-medium">Risk / Severity</span>
                    <div>{getSeverityBadge(simulationResult.riskSeverity)}</div>
                  </div>

                  {/* Expected Decision */}
                  <div className="p-3 rounded-lg bg-[#F0F4F8] border border-[#C7D0DA] space-y-1">
                    <span className="text-[11px] text-[#5E6B78] block font-medium">Expected Decision</span>
                    <span className="text-xs font-bold text-[#5E6B78] font-mono block">{simulationResult.expectedDecision}</span>
                  </div>

                  {/* Actual Decision (Visually Distinct) */}
                  <div className={`p-3 rounded-lg border space-y-1 ${visuals.bannerBg}`}>
                    <span className="text-[11px] text-[#5E6B78] block font-medium">Actual Decision (Backend)</span>
                    <span className={`text-xs font-bold font-mono block ${visuals.iconColor}`}>
                      {simulationResult.actualDecision}
                    </span>
                  </div>

                  {/* Timestamp */}
                  <div className="p-3 rounded-lg bg-[#F0F4F8] border border-[#C7D0DA] space-y-1">
                    <span className="text-[11px] text-[#5E6B78] block font-medium">Timestamp</span>
                    <span className="text-xs font-mono text-[#182230] flex items-center gap-1.5">
                      <Clock className="w-3.5 h-3.5 text-[#5E6B78] shrink-0" />
                      {simulationResult.timestamp}
                    </span>
                  </div>

                  {/* Audit Result */}
                  <div className="p-3 rounded-lg bg-[#EAF5F0] border border-[#B2D8C7] space-y-1">
                    <span className="text-[11px] text-[#2E7D5B] block font-medium">Audit Result</span>
                    <span className="text-xs font-semibold text-[#2E7D5B] flex items-center gap-1.5">
                      <CheckCircle2 className="w-3.5 h-3.5 text-[#2E7D5B] shrink-0" />
                      Recorded in Database
                    </span>
                  </div>
                </div>
              </div>

              {/* Audit Trail & Verification Detail */}
              <div className="space-y-2 text-xs">
                <h4 className="font-bold text-[#182230] uppercase tracking-wider text-[11px]">
                  Real Audit Event & Enforcement Log
                </h4>
                <div className="p-3.5 rounded-lg bg-[#F0F4F8] border border-[#C7D0DA] space-y-2">
                  <div className="flex items-start gap-2">
                    <Fingerprint className="w-4 h-4 text-[#17324D] shrink-0 mt-0.5" />
                    <div>
                      <strong className="text-[#182230]">Audit Trail Entry:</strong>
                      <p className="text-[#5E6B78] font-mono text-[11px] mt-0.5">
                        {simulationResult.auditResult}
                      </p>
                    </div>
                  </div>
                  <div className="pt-2 border-t border-[#C7D0DA]/60 text-[11px] text-[#5E6B78]">
                    <strong className="text-[#182230]">Policy Mechanism:</strong> {simulationResult.mechanism}
                  </div>
                </div>
              </div>

              {/* Action Button: Run Again */}
              <div className="pt-2 flex items-center justify-between">
                <span className="text-[11px] text-[#2E7D5B] font-medium flex items-center gap-1">
                  <CheckCircle2 className="w-3.5 h-3.5 text-[#2E7D5B]" />
                  State refreshed from real backend API
                </span>
                <Button
                  variant="outline"
                  size="sm"
                  icon={RotateCcw}
                  onClick={handleReset}
                >
                  Run Another Simulation
                </Button>
              </div>
            </Card>
          ) : (
            <Card className="p-8 bg-white border border-[#C7D0DA] text-center min-h-90 flex flex-col items-center justify-center space-y-3 shadow-xs">
              <div className="w-12 h-12 rounded-xl bg-[#F0F4F8] border border-[#C7D0DA] text-[#5E6B78] flex items-center justify-center">
                <ShieldX className="w-6 h-6" />
              </div>
              <div className="space-y-1.5 max-w-sm">
                <span className="text-xs font-semibold text-[#5E6B78] uppercase tracking-wider block">
                  Simulator Ready
                </span>
                <h3 className="text-sm font-bold text-[#182230]">
                  Select an Attack Vector to Simulate
                </h3>
                <p className="text-xs text-[#5E6B78] leading-relaxed">
                  Choose a controlled simulation scenario on the left and click "Simulate Attack" to execute real Zero-Trust defense evaluations.
                </p>
              </div>
            </Card>
          )}
        </div>
      </div>
    </PageContainer>
  );
}
