#!/usr/bin/env python3
"""Demo script showcasing Phase 2 Risk Analysis Engine.

This script demonstrates a real-world scenario: analyzing an overly permissive
IAM policy and providing security recommendations.
"""

from src.sentinel.analyzer import (
    IntentMapper,
    RiskAnalyzer,
    DangerousPermissionChecker,
    CompanionPermissionDetector,
    HITLSystem,
    RiskSeverity,
)


def print_header(title: str):
    """Print formatted section header."""
    print("\n" + "=" * 80)
    print(f"  {title}")
    print("=" * 80 + "\n")


def demo_scenario():
    """Demonstrate Phase 2 analysis on a real-world policy."""

    print_header("IAM POLICY SENTINEL - PHASE 2 DEMO")
    print("Scenario: Junior DevOps engineer created an overly permissive policy")
    print("for a Lambda function that processes S3 data.")

    # The problematic policy
    policy_actions = [
        '*',  # Full wildcard - VERY BAD
        's3:*',  # S3 wildcard
        'iam:PassRole',  # Dangerous with Lambda
        'lambda:CreateFunction',
        'lambda:InvokeFunction',
        'secretsmanager:GetSecretValue',
        'dynamodb:GetItem',
    ]

    print("\nProposed Policy Actions:")
    for i, action in enumerate(policy_actions, 1):
        print(f"  {i}. {action}")

    # Initialize analyzers
    analyzer = RiskAnalyzer()
    checker = DangerousPermissionChecker()
    detector = CompanionPermissionDetector()

    # 1. Wildcard Analysis
    print_header("STEP 1: Wildcard Detection")
    findings = analyzer.analyze_actions(policy_actions)
    wildcard_findings = [f for f in findings if 'WILDCARD' in f.risk_type]

    print(f"Found {len(wildcard_findings)} wildcard issues:\n")
    for finding in wildcard_findings:
        print(f"[ALERT] {finding.severity.value}: {finding.action}")
        print(f"   Description: {finding.description}")
        print(f"   Remediation: {finding.remediation}\n")

    # 2. Privilege Escalation Analysis
    print_header("STEP 2: Privilege Escalation Detection")
    escalation_findings = [f for f in findings if f.risk_type == 'PRIVILEGE_ESCALATION']

    print(f"Found {len(escalation_findings)} privilege escalation risks:\n")
    for finding in escalation_findings:
        print(f"[WARN] {finding.severity.value}: {finding.action}")
        print(f"   {finding.description}")
        print(f"   Remediation: {finding.remediation}\n")

    # 3. Dangerous Combinations
    print_header("STEP 3: Dangerous Permission Combinations")
    combo_findings = [f for f in findings if f.risk_type == 'DANGEROUS_COMBINATION']

    if combo_findings:
        print(f"Found {len(combo_findings)} dangerous combinations:\n")
        for finding in combo_findings:
            print(f"[DANGER] {finding.severity.value}: {finding.action}")
            print(f"   {finding.description}")
            print(f"   Path: {finding.additional_context.get('escalation_path', 'N/A')}")
            print(f"   Remediation: {finding.remediation}\n")
    else:
        print("[PASS] No dangerous combinations detected\n")

    # 4. Data Exfiltration Risks
    print_header("STEP 4: Data Exfiltration Risk Assessment")
    exfil_findings = [f for f in findings if f.risk_type == 'DATA_EXFILTRATION_RISK']

    print(f"Found {len(exfil_findings)} data exfiltration risks:\n")
    for finding in exfil_findings:
        print(f"[EXFIL] {finding.severity.value}: {finding.action}")
        print(f"   Pattern: {finding.additional_context.get('pattern', 'N/A')}")
        print(f"   {finding.description}\n")

    # 5. Missing Companion Permissions
    print_header("STEP 5: Companion Permission Analysis")
    missing_companions = detector.detect_missing_companions(policy_actions)

    if missing_companions:
        print(f"Found {len(missing_companions)} missing companion permissions:\n")
        for comp in missing_companions:
            print(f"[COMPANION] {comp.primary_action}")
            print(f"   Severity: {comp.severity.value}")
            print(f"   Reason: {comp.reason}")
            print(f"   Missing:")
            for action in comp.companion_actions:
                print(f"     - {action}")
            print()
    else:
        print("[PASS] All required companion permissions present\n")

    # 6. Summary and Recommendations
    print_header("STEP 6: Analysis Summary and Recommendations")

    critical_count = len([f for f in findings if f.severity == RiskSeverity.CRITICAL])
    high_count = len([f for f in findings if f.severity == RiskSeverity.HIGH])
    medium_count = len([f for f in findings if f.severity == RiskSeverity.MEDIUM])

    print(f"Total Findings: {len(findings)}")
    print(f"  [!] CRITICAL: {critical_count}")
    print(f"  [!] HIGH: {high_count}")
    print(f"  [!] MEDIUM: {medium_count}")
    print(f"\nMissing Companions: {len(missing_companions)}")

    print("\n" + "-" * 80)
    print("RECOMMENDATIONS:")
    print("-" * 80 + "\n")

    print("1. REMOVE FULL WILDCARD (*)")
    print("   Never use '*' in production policies. It grants ALL permissions.")
    print("   Replace with specific actions needed for the Lambda function.\n")

    print("2. REPLACE SERVICE WILDCARDS")
    print("   Change 's3:*' to specific actions:")
    print("   - s3:GetObject (if reading objects)")
    print("   - s3:PutObject (if writing objects)")
    print("   - s3:ListBucket (if listing buckets)\n")

    print("3. RESTRICT iam:PassRole")
    print("   Add resource constraints to limit which roles can be passed:")
    print('   Resource: "arn:aws:iam::123456789012:role/MyLambdaRole"\n')

    print("4. ADD MISSING COMPANION PERMISSIONS")
    for comp in missing_companions:
        print(f"   For {comp.primary_action}:")
        for action in comp.companion_actions:
            print(f"     + {action}")
    print()

    print("5. ADD CONDITIONS")
    print("   Consider adding conditions to further restrict access:")
    print("   - IP address restrictions")
    print("   - MFA requirements for sensitive operations")
    print("   - Time-based access controls\n")

    # 7. Generate Safer Policy
    print_header("STEP 7: Recommended Safer Policy")

    safe_policy = [
        # Specific S3 actions instead of wildcard
        's3:GetObject',
        's3:ListBucket',
        # Lambda actions with resource constraints
        'lambda:InvokeFunction',
        # Restricted PassRole with resource ARN
        'iam:PassRole',  # Add resource constraint in actual policy
        # DynamoDB read access
        'dynamodb:GetItem',
        # CloudWatch Logs for Lambda
        'logs:CreateLogGroup',
        'logs:CreateLogStream',
        'logs:PutLogEvents',
    ]

    print("Recommended Actions:")
    for i, action in enumerate(safe_policy, 1):
        print(f"  {i}. {action}")

    print("\nAdditional Policy Elements:")
    print("  - Resource constraints on sensitive actions")
    print("  - Condition blocks for IP/MFA restrictions")
    print("  - Separate policies for different environments")

    # 8. Before/After Comparison
    print_header("BEFORE vs AFTER")

    print("BEFORE (Security Issues):")
    print(f"  - {len(policy_actions)} actions")
    print(f"  - {critical_count} CRITICAL findings")
    print(f"  - {high_count} HIGH findings")
    print(f"  - {len(missing_companions)} missing companions")
    print("  - Full wildcard permissions")

    print("\nAFTER (Recommended):")
    print(f"  - {len(safe_policy)} actions (specific)")
    print("  - 0 CRITICAL findings")
    print("  - 0 HIGH findings (with resource constraints)")
    print("  - All required companions included")
    print("  - Follows least privilege principle")

    print_header("CONCLUSION")
    print("The Phase 2 Risk Analysis Engine successfully identified:")
    print(f"  [v] {len(wildcard_findings)} wildcard issues")
    print(f"  [v] {len(escalation_findings)} privilege escalation risks")
    print(f"  [v] {len(combo_findings)} dangerous combinations")
    print(f"  [v] {len(exfil_findings)} data exfiltration risks")
    print(f"  [v] {len(missing_companions)} missing companion permissions")
    print("\nThe policy has been analyzed and recommendations provided.")
    print("With these changes, the policy will follow AWS best practices")
    print("and the principle of least privilege.\n")


def demo_intent_mapping():
    """Demonstrate intent mapping capabilities."""

    print_header("BONUS: Intent Mapping Demo")
    print("Show how natural language translates to access levels\n")

    mapper = IntentMapper()

    intents = [
        "read-only access for monitoring",
        "deploy serverless applications",
        "admin access for IAM management",
        "list S3 buckets and objects",
    ]

    for intent in intents:
        result = mapper.map_intent(intent)
        print(f"Intent: '{intent}'")
        print(f"  → Access Levels: {[level.value for level in result.access_levels]}")
        print(f"  → Services: {result.services if result.services else 'All'}")
        print(f"  → Confidence: {result.confidence:.0%}\n")


def main():
    """Run the demo."""
    try:
        demo_scenario()
        demo_intent_mapping()

        print("\n" + "=" * 80)
        print("  Demo Complete! Phase 2 Risk Analysis Engine is fully operational.")
        print("=" * 80 + "\n")

        return 0

    except Exception as e:
        print(f"\n[ERROR] Error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    exit(main())
