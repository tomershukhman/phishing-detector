import React from "react";

interface ActionBarProps {
  isLoading: boolean;
  onCheck: () => Promise<void>;
  onExport?: () => void;
  isAutoAnalyzed?: boolean;
  analysisTimestamp?: number;
}

const ActionBar: React.FC<ActionBarProps> = ({
  isLoading,
  onCheck,
  onExport,
  isAutoAnalyzed = false,
  analysisTimestamp = 0
}) => {
  // Format timestamp as a readable string
  const getTimestampString = () => {
    if (!analysisTimestamp) return '';

    const date = new Date(analysisTimestamp);
    return date.toLocaleTimeString();
  };

  return (
    <div className="action-bar">
      {isAutoAnalyzed && (
        <div className="auto-analysis-badge" title="This page was automatically analyzed">
          Auto-analyzed
        </div>
      )}

      <div className="action-buttons">
        <button
          className="analyze-btn"
          onClick={onCheck}
          disabled={isLoading}
        >
          {isLoading ? 'Analyzing...' : 'Check Now'}
        </button>



        {onExport && (
          <button
            className="export-btn"
            onClick={onExport}
            disabled={!onExport}
            title="Export analysis data as JSON"
          >
            Export
          </button>
        )}
      </div>

      {analysisTimestamp > 0 && (
        <div className="timestamp" title="Time when analysis was completed">
          Analyzed at: {getTimestampString()}
        </div>
      )}
    </div>
  );
};

export default ActionBar; 