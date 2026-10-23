import * as vscode from "vscode";
import { ScanSettings, Severity } from "./model";

export interface ExtensionSettings extends ScanSettings {
  executablePath: string;
  pythonPath: string;
  showSuppressedFindings: boolean;
}

export function readSettings(scope?: vscode.ConfigurationScope): ExtensionSettings {
  const config = vscode.workspace.getConfiguration("aegisai", scope);
  return {
    executablePath: config.get<string>("executablePath", "aegisai"),
    pythonPath: config.get<string>("pythonPath", ""),
    profile: config.get<string>("profile", "all"),
    severityThreshold: config.get<Severity>("severityThreshold", "informational"),
    exclude: config.get<string[]>("exclude", []),
    noIntegrations: config.get<boolean>("noIntegrations", false),
    timeoutSeconds: config.get<number>("timeoutSeconds", 300),
    extraArgs: config.get<string[]>("extraArgs", []),
    showSuppressedFindings: config.get<boolean>("showSuppressedFindings", false),
  };
}
