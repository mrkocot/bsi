load("@io_bazel_rules_kotlin//kotlin:jvm.bzl", "kt_jvm_binary")
load("@io_bazel_rules_kotlin//kotlin:jvm.bzl", "kt_jvm_library")

kt_jvm_binary (
    name = "main",
    srcs = glob(["*.kt"]),
    main_class = "bouncy.BouncyMain",
    deps = [
        "@maven//:org_bouncycastle_bcprov_jdk18on",
    ],
    data = ["@//cypher/resources:images/raccoon.jpg"]
)
