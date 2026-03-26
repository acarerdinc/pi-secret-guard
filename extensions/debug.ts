/**
 * Debug extension to check if tool_call events are being received
 */
import type { ExtensionAPI } from "@mariozechner/pi-coding-agent";

console.log("[DEBUG] pi-secret-guard debug extension loaded");

export default function (pi: ExtensionAPI) {
    console.log("[DEBUG] Extension factory called");
    
    pi.on("tool_call", async (event, ctx) => {
        console.log("[DEBUG] tool_call event received");
        console.log("[DEBUG] event type:", event.type);
        console.log("[DEBUG] event.toolName:", (event as any).toolName);
        console.log("[DEBUG] event.input:", JSON.stringify((event as any).input));
        
        // Check for bash
        if ((event as any).toolName !== "bash") {
            console.log("[DEBUG] Not a bash event");
            return;
        }
        
        const command = (event as any).input?.command;
        console.log("[DEBUG] Bash command:", command);
        
        if (command && command.includes("git")) {
            console.log("[DEBUG] Git command detected!");
        }
        
        return; // Don't block anything
    });
}
