import React from "react";

interface HeaderProps {
  url: string;
}

const Header: React.FC<HeaderProps> = ({ url }) => {
  return (
    <header>
      <h1>Phishing Detector</h1>
      <div className="url-display">
        <span className="url-label">URL:</span>
        <span className="url-value">{url || "Loading..."}</span>
      </div>
    </header>
  );
};

export default Header; 