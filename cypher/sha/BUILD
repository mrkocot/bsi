load("@io_bazel_rules_kotlin//kotlin:jvm.bzl", "kt_jvm_binary")

MESSAGES = [
    "@//cypher/resources:messages/message1.txt",
    "@//cypher/resources:messages/message2.txt",
]

kt_jvm_binary(
    name = "main",
    main_class = "sha.ShaMain",
    srcs = ["SHA256.kt", "ShaMain.kt"],
    deps = ["@//cypher/agno:full"],
    data = MESSAGES,
)