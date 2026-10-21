"""Known IAM privilege escalation paths.

Based on the publicly documented techniques catalogued by Rhino Security Labs
("AWS IAM Privilege Escalation – Methods and Mitigation") and later research.
Each path lists the actions that together let a principal gain more privileges
than it was given.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class EscalationPath:
    name: str
    actions: tuple[str, ...]
    description: str


ESCALATION_PATHS: tuple[EscalationPath, ...] = (
    EscalationPath(
        "Create new policy version",
        ("iam:CreatePolicyVersion",),
        "Can publish a new default version of a managed policy with any permissions.",
    ),
    EscalationPath(
        "Set default policy version",
        ("iam:SetDefaultPolicyVersion",),
        "Can switch a managed policy to an older, more permissive version.",
    ),
    EscalationPath(
        "Create access key for another user",
        ("iam:CreateAccessKey",),
        "Can mint access keys for other users and act as them.",
    ),
    EscalationPath(
        "Create console login profile",
        ("iam:CreateLoginProfile",),
        "Can set a console password on a user that has none and sign in as them.",
    ),
    EscalationPath(
        "Update console login profile",
        ("iam:UpdateLoginProfile",),
        "Can reset another user's console password.",
    ),
    EscalationPath(
        "Attach managed policy to user",
        ("iam:AttachUserPolicy",),
        "Can attach AdministratorAccess to a user.",
    ),
    EscalationPath(
        "Attach managed policy to group",
        ("iam:AttachGroupPolicy",),
        "Can attach AdministratorAccess to a group the caller belongs to.",
    ),
    EscalationPath(
        "Attach managed policy to role",
        ("iam:AttachRolePolicy",),
        "Can attach AdministratorAccess to a role the caller can assume.",
    ),
    EscalationPath(
        "Put inline user policy",
        ("iam:PutUserPolicy",),
        "Can write an inline policy with any permissions onto a user.",
    ),
    EscalationPath(
        "Put inline group policy",
        ("iam:PutGroupPolicy",),
        "Can write an inline policy with any permissions onto a group.",
    ),
    EscalationPath(
        "Put inline role policy",
        ("iam:PutRolePolicy",),
        "Can write an inline policy with any permissions onto a role.",
    ),
    EscalationPath(
        "Add user to group",
        ("iam:AddUserToGroup",),
        "Can add a user to a more privileged group, such as an admin group.",
    ),
    EscalationPath(
        "Update role trust policy",
        ("iam:UpdateAssumeRolePolicy", "sts:AssumeRole"),
        "Can rewrite a privileged role's trust policy to trust the caller, then assume it.",
    ),
    EscalationPath(
        "Pass role to new EC2 instance",
        ("iam:PassRole", "ec2:RunInstances"),
        "Can launch an instance with a privileged instance profile and use its credentials.",
    ),
    EscalationPath(
        "Pass role to new Lambda function",
        ("iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"),
        "Can create and run a function that executes with a privileged role.",
    ),
    EscalationPath(
        "Pass role to Lambda via event source",
        ("iam:PassRole", "lambda:CreateFunction", "lambda:CreateEventSourceMapping"),
        "Can create a function with a privileged role and trigger it from an event source.",
    ),
    EscalationPath(
        "Update existing Lambda code",
        ("lambda:UpdateFunctionCode",),
        "Can replace the code of a function that already runs with a privileged role.",
    ),
    EscalationPath(
        "Pass role to Glue dev endpoint",
        ("iam:PassRole", "glue:CreateDevEndpoint"),
        "Can create a Glue dev endpoint with a privileged role and SSH into it.",
    ),
    EscalationPath(
        "Update Glue dev endpoint",
        ("glue:UpdateDevEndpoint",),
        "Can add an SSH key to an existing Glue dev endpoint and use its role.",
    ),
    EscalationPath(
        "Pass role to CloudFormation stack",
        ("iam:PassRole", "cloudformation:CreateStack"),
        "Can create a stack that runs with a privileged role and provisions anything.",
    ),
    EscalationPath(
        "Pass role to Data Pipeline",
        ("iam:PassRole", "datapipeline:CreatePipeline", "datapipeline:PutPipelineDefinition"),
        "Can run arbitrary commands in a pipeline that uses a privileged role.",
    ),
    EscalationPath(
        "Pass role to SageMaker notebook",
        (
            "iam:PassRole",
            "sagemaker:CreateNotebookInstance",
            "sagemaker:CreatePresignedNotebookInstanceUrl",
        ),
        "Can open a notebook that runs with a privileged role.",
    ),
    EscalationPath(
        "Pass role to ECS task",
        ("iam:PassRole", "ecs:RegisterTaskDefinition", "ecs:RunTask"),
        "Can run a container whose task role is privileged.",
    ),
)
