import React, { useState } from 'react';
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
  RotateCcw
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

const SCENARIOS = [
  {
    id: 'UNAUTHORIZED_ACCESS',
    name: 'Unauthorized Paper Access',
    description: 'Simulates an unverified terminal attempting direct paper access without proper officer authorization.',
    mechanism: 'TrustGuard checks client credentials against the access policy and immediately rejects the connection.',
  },
  {
    id: 'INVALID_QUORUM',
    name: 'Invalid Quorum Request',
    description: 'Simulates an attempt to request access with insufficient officer signatures.',
    mechanism: 'Quorum validation verifies that all required officer approvals are present before permitting access.',
  },
  {
    id: 'UNAUTHORIZED_RECONSTRUCTION',
    name: 'Access Outside Exam Window',
    description: 'Simulates an attempt to access question papers outside the designated examination schedule.',
    mechanism: 'Schedule policy prevents question paper release until the official examination window opens.',
  },
];

export function AttackSimulatorPage() {
  const { triggerAttackSimulation } = useTrustGuard();
  const [selectedPaper, setSelectedPaper] = useState(TARGET_PAPERS[0].id);
  const [selectedScenario, setSelectedScenario] = useState(SCENARIOS[0].id);
  const [isSimulating, setIsSimulating] = useState(false);
  const [simulationResult, setSimulationResult] = useState(null);

  const handleSimulate = () => {
    setIsSimulating(true);
    setSimulationResult(null);

    setTimeout(() => {
      setIsSimulating(false);
      const scenarioObj = SCENARIOS.find((s) => s.id === selectedScenario);
      const paperObj = TARGET_PAPERS.find((p) => p.id === selectedPaper);

      // Trigger shared state update across entire app
      triggerAttackSimulation({
        scenarioName: scenarioObj?.name,
        paperId: selectedPaper,
      });

      setSimulationResult({
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
        paperId: selectedPaper,
        paperName: paperObj?.name,
        scenarioId: selectedScenario,
        scenarioName: scenarioObj?.name,
        scenarioDesc: scenarioObj?.description,
        mechanism: scenarioObj?.mechanism,
        eventId: `SIM-${Math.floor(100000 + Math.random() * 900000)}`,
      });
    }, 300);
  };

  const handleReset = () => {
    setSimulationResult(null);
  };

  const activeScenario = SCENARIOS.find((s) => s.id === selectedScenario) || SCENARIOS[0];

  return (
    <PageContainer
      title="Attack Simulator"
      subtitle="Simulate a controlled unauthorized access scenario against a protected question paper."
      action={
        <Badge variant="default" size="sm">
          Controlled Sandbox Environment
        </Badge>
      }
    >
      {/* Guidance Banner */}
      <Card className="p-4 bg-white border border-[#C7D0DA] shadow-xs">
        <div className="flex items-start gap-3 text-xs">
          <div className="p-2 rounded-lg bg-[#F0F5F9] border border-[#D5DDE5] text-[#17324D] shrink-0">
            <ShieldCheck className="w-4 h-4" />
          </div>
          <div>
            <h3 className="font-bold text-[#17324D]">
              Interactive Security Verification Sandbox
            </h3>
            <p className="text-[#667085] mt-0.5 leading-relaxed">
              Verify how access controls, quorum threshold verification, and examination release window schedules automatically intercept and block unauthorized attempts.
            </p>
          </div>
        </div>
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Configuration Controls */}
        <div className="lg:col-span-5 space-y-4">
          <Card
            className="p-5 bg-white border border-[#C7D0DA] space-y-4 shadow-xs"
            header={
              <h2 className="text-sm font-bold text-[#17324D] flex items-center gap-2">
                <Play className="w-4 h-4 text-[#17324D]" />
                Simulation Configuration
              </h2>
            }
          >
            {/* Target Paper Selection */}
            <div className="space-y-1.5">
              <label htmlFor="target-paper" className="block text-xs font-semibold text-[#344054]">
                Target Question Paper
              </label>
              <select
                id="target-paper"
                value={selectedPaper}
                onChange={(e) => setSelectedPaper(e.target.value)}
                className="w-full bg-white border border-[#C7D0DA] rounded-lg text-[#1F2933] text-xs py-2.5 px-3 focus:outline-none focus:ring-2 focus:ring-[#17324D]/10 focus:border-[#17324D] cursor-pointer"
              >
                {TARGET_PAPERS.map((paper) => (
                  <option key={paper.id} value={paper.id}>
                    {paper.name}
                  </option>
                ))}
              </select>
            </div>

            {/* Scenario Selection */}
            <div className="space-y-1.5">
              <label htmlFor="attack-scenario" className="block text-xs font-semibold text-[#344054]">
                Attack Scenario
              </label>
              <select
                id="attack-scenario"
                value={selectedScenario}
                onChange={(e) => setSelectedScenario(e.target.value)}
                className="w-full bg-white border border-[#C7D0DA] rounded-lg text-[#1F2933] text-xs py-2.5 px-3 focus:outline-none focus:ring-2 focus:ring-[#17324D]/10 focus:border-[#17324D] cursor-pointer"
              >
                {SCENARIOS.map((scenario) => (
                  <option key={scenario.id} value={scenario.id}>
                    {scenario.name}
                  </option>
                ))}
              </select>
            </div>

            {/* Selected Scenario Explanation Box */}
            <div className="p-3 rounded-lg bg-[#F1F4F7] border border-[#D5DDE5] text-xs space-y-1">
              <span className="text-[#344054] font-bold block">Scenario Objective:</span>
              <p className="text-[#475467] leading-snug">
                {activeScenario.description}
              </p>
            </div>

            {/* Actions */}
            <div className="pt-2 flex items-center gap-2">
              <Button
                variant="primary"
                size="md"
                className="w-full justify-center font-semibold"
                icon={Play}
                onClick={handleSimulate}
                loading={isSimulating}
              >
                {isSimulating ? 'Executing Simulation...' : 'Simulate Attack'}
              </Button>
              {simulationResult && (
                <Button
                  variant="outline"
                  size="md"
                  icon={RotateCcw}
                  onClick={handleReset}
                  aria-label="Reset simulation"
                />
              )}
            </div>
          </Card>
        </div>

        {/* Right Column: Simulation Output / State Display */}
        <div className="lg:col-span-7">
          {simulationResult ? (
            <Card className="p-5 bg-white border border-[#C7D0DA] space-y-5 shadow-xs">
              {/* Threat Result Header Banner */}
              <div className="p-4 rounded-xl bg-[#FEF3F2] border border-[#FECDCA] flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-lg bg-white text-[#C44747] border border-[#FECDCA] shrink-0 shadow-xs">
                    <ShieldAlert className="w-5 h-5" />
                  </div>
                  <div>
                    <span className="text-xs font-mono font-bold text-[#C44747] uppercase block">
                      Security Alert Response
                    </span>
                    <h3 className="text-sm sm:text-base font-bold text-[#1F2933]">
                      THREAT DETECTED — Access Blocked
                    </h3>
                  </div>
                </div>
                <Badge variant="danger" size="md">
                  Attack Neutralized
                </Badge>
              </div>

              {/* Four Status Badges / Cards */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
                <div className="p-3 rounded-lg bg-[#F1F4F7] border border-[#D5DDE5] text-center">
                  <span className="text-[11px] text-[#667085] block mb-1 font-medium">Threat Status</span>
                  <span className="text-xs font-bold text-[#C44747]">DETECTED</span>
                </div>
                <div className="p-3 rounded-lg bg-[#F1F4F7] border border-[#D5DDE5] text-center">
                  <span className="text-[11px] text-[#667085] block mb-1 font-medium">Access Gate</span>
                  <span className="text-xs font-bold text-[#C44747]">Blocked</span>
                </div>
                <div className="p-3 rounded-lg bg-[#F1F4F7] border border-[#D5DDE5] text-center">
                  <span className="text-[11px] text-[#667085] block mb-1 font-medium">Authorization</span>
                  <span className="text-xs font-bold text-[#B7791F]">Failed</span>
                </div>
                <div className="p-3 rounded-lg bg-[#F1F4F7] border border-[#D5DDE5] text-center">
                  <span className="text-[11px] text-[#667085] block mb-1 font-medium">Audit Ledger</span>
                  <span className="text-xs font-bold text-[#2E7D5B]">Event Created</span>
                </div>
              </div>

              {/* Execution Diagnostics */}
              <div className="space-y-2 text-xs">
                <h4 className="font-bold text-[#344054] uppercase tracking-wider text-[11px]">
                  Security Enforcement Summary
                </h4>
                <div className="p-3.5 rounded-lg bg-[#F1F4F7] border border-[#D5DDE5] space-y-2.5">
                  <div className="flex items-start gap-2">
                    <XCircle className="w-4 h-4 text-[#C44747] shrink-0 mt-0.5" />
                    <div>
                      <strong className="text-[#1F2933]">1. Verification Check:</strong>
                      <span className="text-[#667085] ml-1">
                        Client presented invalid or unauthorized credentials.
                      </span>
                    </div>
                  </div>

                  <div className="flex items-start gap-2">
                    <XCircle className="w-4 h-4 text-[#C44747] shrink-0 mt-0.5" />
                    <div>
                      <strong className="text-[#1F2933]">2. Quorum Policy:</strong>
                      <span className="text-[#667085] ml-1">
                        Required multi-officer sign-off was not satisfied.
                      </span>
                    </div>
                  </div>

                  <div className="flex items-start gap-2">
                    <CheckCircle2 className="w-4 h-4 text-[#2E7D5B] shrink-0 mt-0.5" />
                    <div>
                      <strong className="text-[#1F2933]">3. Question Paper State:</strong>
                      <span className="text-[#2E7D5B] ml-1 font-semibold">
                        Remains protected and encrypted. Zero data exposed.
                      </span>
                    </div>
                  </div>

                  <div className="flex items-start gap-2">
                    <CheckCircle2 className="w-4 h-4 text-[#2E7D5B] shrink-0 mt-0.5" />
                    <div>
                      <strong className="text-[#1F2933]">4. Audit Record Committed:</strong>
                      <span className="text-[#344054] ml-1 font-mono text-[11px] font-semibold">
                        {simulationResult.eventId} (Logged at {simulationResult.timestamp})
                      </span>
                    </div>
                  </div>
                </div>
              </div>

              {/* Defense Mechanism Summary */}
              <div className="p-3 rounded-lg bg-[#F1F4F7] border border-[#D5DDE5] text-xs">
                <span className="text-[#344054] font-bold block mb-0.5">Defensive Mechanism:</span>
                <p className="text-[#475467] leading-relaxed">
                  {simulationResult.mechanism}
                </p>
              </div>
            </Card>
          ) : (
            <Card className="p-8 bg-white border border-[#C7D0DA] text-center min-h-[320px] flex flex-col items-center justify-center space-y-3 shadow-xs">
              <div className="w-12 h-12 rounded-xl bg-[#F1F4F7] border border-[#D5DDE5] text-[#98A2B3] flex items-center justify-center">
                <ShieldX className="w-6 h-6" />
              </div>
              <div className="space-y-1 max-w-sm">
                <h3 className="text-sm font-bold text-[#1F2933]">
                  Ready to Run Simulation
                </h3>
                <p className="text-xs text-[#667085] leading-relaxed">
                  Select a target question paper and attack scenario from the left panel, then click <strong>Simulate Attack</strong> to observe the protective response.
                </p>
              </div>
            </Card>
          )}
        </div>
      </div>
    </PageContainer>
  );
}
