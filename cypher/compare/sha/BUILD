load("@io_bazel_rules_kotlin//kotlin:jvm.bzl", "kt_jvm_binary")

package (
    default_visibility = ["@//visibility:public"]
)

kt_jvm_binary (
    name = "main",
    srcs = glob(["*.kt"]),
    main_class = "compare.sha.CompareSha",
    deps = [
        "@maven//:org_apache_commons_commons_math3",
        "@//cypher/agno:full",
    ],
    data = ["@//cypher/resources:hash/hash.csv"],
)

py_binary (
    name = "simgen",
    srcs = ["python/simgen.py"],
    main = "python/simgen.py",
)
