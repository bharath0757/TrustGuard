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
    name: 'Unauthorized question-paper access',
    description: 'Simulates an unverified terminal attempting direct paper access without proper officer authorization.',
    mechanism: 'TrustGuard checks client credentials against the access policy and immediately rejects the connection.',
  },
  {
    id: 'INVALID_QUORUM',
    name: 'Invalid quorum request',
    description: 'Simulates an attempt to request access with insufficient officer signatures.',
    mechanism: 'Quorum validation verifies that all required officer approvals are present before permitting access.',
  },
  {
    id: 'UNAUTHORIZED_RECONSTRUCTION',
    name: 'Unauthorized reconstruction request',
    description: 'Simulates an attempt to reconstruct paper fragments outside the designated examination schedule.',
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
    }, 400);
  };

  const handleReset = () => {
    setSimulationResult(null);
  };

  const activeScenario = SCENARIOS.find((s) => s.id === selectedScenario) || SCENARIOS[0];

  return (
    <PageContainer
      title="Attack Simulator"
      subtitle="Run a controlled demonstration of unauthorized access scenarios."
    >
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* LEFT COLUMN: Simulation Controls */}
        <div className="lg:col-span-5 space-y-4">
          <Card
            className="p-5 bg-white border border-[#C7D0DA] space-y-4 shadow-xs"
            header={
              <h2 className="text-sm font-bold text-[#17324D] flex items-center gap-2">
                <Play className="w-4 h-4 text-[#17324D]" />
                Simulation Controls
              </h2>
            }
          >
            {/* Target Paper Selection */}
            <div className="space-y-1.5">
              <label htmlFor="target-paper" className="block text-xs font-semibold text-[#182230]">
                Target paper
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

            {/* Scenario Selection */}
            <div className="space-y-1.5">
              <label htmlFor="attack-scenario" className="block text-xs font-semibold text-[#182230]">
                Scenario
              </label>
              <select
                id="attack-scenario"
                value={selectedScenario}
                onChange={(e) => setSelectedScenario(e.target.value)}
                className="w-full bg-white border border-[#C7D0DA] rounded-lg text-[#182230] text-xs py-2.5 px-3 focus:outline-none focus:ring-2 focus:ring-[#17324D]/10 focus:border-[#17324D] cursor-pointer font-medium"
              >
                {SCENARIOS.map((scenario) => (
                  <option key={scenario.id} value={scenario.id}>
                    {scenario.name}
                  </option>
                ))}
              </select>
            </div>

            {/* Selected Scenario Explanation Box */}
            <div className="p-3 rounded-lg bg-[#F0F4F8] border border-[#C7D0DA] text-xs space-y-1">
              <span className="text-[#182230] font-bold block">Scenario Detail:</span>
              <p className="text-[#5E6B78] leading-snug">
                {activeScenario.description}
              </p>
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
                {isSimulating ? 'Executing Simulation...' : 'Simulate Attack'}
              </Button>

              <p className="text-[11px] text-[#5E6B78] text-center italic">
                Simulation only. No real examination content is accessed.
              </p>
            </div>
          </Card>
        </div>

        {/* RIGHT COLUMN: Simulation Result Panel */}
        <div className="lg:col-span-7">
          {simulationResult ? (
            <Card className="p-5 bg-white border border-[#C7D0DA] space-y-5 shadow-xs">
              {/* Threat Result Header Banner with subtle red accent */}
              <div className="p-4 rounded-xl bg-[#FDF2F2] border border-[#F2C2C2] flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-lg bg-white text-[#C44747] border border-[#F2C2C2] shrink-0 shadow-2xs">
                    <ShieldAlert className="w-5 h-5" />
                  </div>
                  <div>
                    <span className="text-[11px] font-mono font-bold text-[#C44747] uppercase block">
                      THREAT DETECTED
                    </span>
                    <h3 className="text-sm sm:text-base font-bold text-[#182230]">
                      {simulationResult.scenarioName}
                    </h3>
                  </div>
                </div>
                <Badge variant="danger" size="md" className="shrink-0">
                  ACCESS BLOCKED
                </Badge>
              </div>

              {/* Four Status Cards */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
                <div className="p-3 rounded-lg bg-[#F0F4F8] border border-[#C7D0DA] text-center">
                  <span className="text-[11px] text-[#5E6B78] block mb-1 font-medium">Target</span>
                  <span className="text-xs font-bold text-[#17324D] font-mono">{simulationResult.paperId}</span>
                </div>
                <div className="p-3 rounded-lg bg-[#FDF2F2] border border-[#F2C2C2] text-center">
                  <span className="text-[11px] text-[#5E6B78] block mb-1 font-medium">Decision</span>
                  <span className="text-xs font-bold text-[#C44747]">ACCESS BLOCKED</span>
                </div>
                <div className="p-3 rounded-lg bg-[#FAF3E7] border border-[#E8D4B5] text-center">
                  <span className="text-[11px] text-[#5E6B78] block mb-1 font-medium">Quorum</span>
                  <span className="text-xs font-bold text-[#B7791F]">Insufficient</span>
                </div>
                <div className="p-3 rounded-lg bg-[#EAF5F0] border border-[#B2D8C7] text-center">
                  <span className="text-[11px] text-[#5E6B78] block mb-1 font-medium">Audit</span>
                  <span className="text-xs font-bold text-[#2E7D5B]">Recorded</span>
                </div>
              </div>

              {/* 4-Step Progression Sequence */}
              <div className="space-y-2 text-xs">
                <h4 className="font-bold text-[#182230] uppercase tracking-wider text-[11px]">
                  Enforcement Progression Sequence
                </h4>
                <div className="p-3.5 rounded-lg bg-[#F0F4F8] border border-[#C7D0DA] space-y-2.5">
                  {/* Step 1 */}
                  <div className="flex items-start gap-2.5">
                    <span className="w-5 h-5 rounded-full bg-[#EEF4F9] text-[#17324D] border border-[#C7D0DA] text-xs font-bold flex items-center justify-center shrink-0 mt-0.5">
                      1
                    </span>
                    <div>
                      <strong className="text-[#182230]">Request received:</strong>
                      <span className="text-[#5E6B78] ml-1">
                        Access attempt logged at {simulationResult.timestamp}.
                      </span>
                    </div>
                  </div>

                  {/* Step 2 */}
                  <div className="flex items-start gap-2.5">
                    <span className="w-5 h-5 rounded-full bg-[#FAF3E7] text-[#B7791F] border border-[#E8D4B5] text-xs font-bold flex items-center justify-center shrink-0 mt-0.5">
                      2
                    </span>
                    <div>
                      <strong className="text-[#182230]">Authorization checked:</strong>
                      <span className="text-[#5E6B78] ml-1">
                        Client credentials and officer quorum signatures evaluated.
                      </span>
                    </div>
                  </div>

                  {/* Step 3 */}
                  <div className="flex items-start gap-2.5">
                    <span className="w-5 h-5 rounded-full bg-[#FDF2F2] text-[#C44747] border border-[#F2C2C2] text-xs font-bold flex items-center justify-center shrink-0 mt-0.5">
                      3
                    </span>
                    <div>
                      <strong className="text-[#182230]">Access blocked:</strong>
                      <span className="text-[#C44747] ml-1 font-semibold">
                        Request rejected. Question paper remains zero-trust encrypted.
                      </span>
                    </div>
                  </div>

                  {/* Step 4 */}
                  <div className="flex items-start gap-2.5">
                    <span className="w-5 h-5 rounded-full bg-[#EEF4F9] text-[#3E6B8C] border border-[#C7D0DA] text-xs font-bold flex items-center justify-center shrink-0 mt-0.5">
                      4
                    </span>
                    <div>
                      <strong className="text-[#182230]">Security alert recorded:</strong>
                      <span className="text-[#3E6B8C] ml-1 font-mono text-[11px] font-semibold">
                        Incident {simulationResult.eventId} committed to threat log & audit trail.
                      </span>
                    </div>
                  </div>
                </div>
              </div>

              {/* Action Button: Run Again */}
              <div className="pt-2 flex justify-end">
                <Button
                  variant="outline"
                  size="sm"
                  icon={RotateCcw}
                  onClick={handleReset}
                >
                  Run Again
                </Button>
              </div>
            </Card>
          ) : (
            <Card className="p-8 bg-white border border-[#C7D0DA] text-center min-h-[320px] flex flex-col items-center justify-center space-y-3 shadow-xs">
              <div className="w-12 h-12 rounded-xl bg-[#F0F4F8] border border-[#C7D0DA] text-[#5E6B78] flex items-center justify-center">
                <ShieldX className="w-6 h-6" />
              </div>
              <div className="space-y-1.5 max-w-sm">
                <span className="text-xs font-semibold text-[#5E6B78] uppercase tracking-wider block">
                  Status: Ready
                </span>
                <h3 className="text-sm font-bold text-[#182230]">
                  Simulation Ready
                </h3>
                <p className="text-xs text-[#5E6B78] leading-relaxed">
                  Choose a scenario and start the simulation.
                </p>
              </div>
            </Card>
          )}
        </div>
      </div>
    </PageContainer>
  );
}
