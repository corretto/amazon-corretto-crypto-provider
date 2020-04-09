// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider.coverage;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.jacoco.core.analysis.Analyzer;
import org.jacoco.core.analysis.CoverageBuilder;
import org.jacoco.core.analysis.IBundleCoverage;
import org.jacoco.core.tools.ExecFileLoader;
import org.jacoco.report.DirectorySourceFileLocator;
import org.jacoco.report.FileMultiReportOutput;
import org.jacoco.report.IReportVisitor;
import org.jacoco.report.MultiReportVisitor;
import org.jacoco.report.MultiSourceFileLocator;
import org.jacoco.report.html.HTMLFormatter;
import org.jacoco.report.xml.XMLFormatter;

public class ReportGenerator {

    // 0. Name
    // 1. ExecFileName
    // 2. ClassDir
    // 3. SrcDir
    // 4. Result dir
    public static void main(final String[] args) throws Exception {
        final String name = args[0];
        final String execFileName = args[1];
        final String classDirName = args[2];
        final String srcDirName = args[3];
        final File resultDir = new File(args[4]);
        if (!resultDir.exists()) {
            resultDir.mkdir();
        }
        final File resultHtmlDir = new File(resultDir, "html");
        if (!resultHtmlDir.exists()) {
            resultHtmlDir.mkdir();
        }
        final File xmlFile = new File(resultDir, "coverage-report.xml");

        generateReports(name, execFileName, classDirName, srcDirName, resultHtmlDir, xmlFile);
        generateBrazilCoverage(xmlFile, resultDir);
    }

    private static void generateReports(final String name, final String execFileName, final String classDirName,
            final String srcDirName, final File resultHtmlDir, final File xmlFile) throws IOException,
            FileNotFoundException {
        final ExecFileLoader execLoader = new ExecFileLoader();
        execLoader.load(new File(execFileName));

        final CoverageBuilder coverageBuilder = new CoverageBuilder();
        final Analyzer analyzer = new Analyzer(execLoader.getExecutionDataStore(), coverageBuilder);

        for (final File f : findFiles(new File(classDirName), ".class")) {
            analyzer.analyzeAll(f);
        }

        final IBundleCoverage bundle = coverageBuilder.getBundle(name);

        final List<IReportVisitor> visitors = new ArrayList<IReportVisitor>();

        try (final FileOutputStream xmlOut = new FileOutputStream(xmlFile)) {
            visitors.add(new XMLFormatter().createVisitor(xmlOut));
            visitors.add(new HTMLFormatter().createVisitor(new FileMultiReportOutput(resultHtmlDir)));
            final MultiReportVisitor visitor = new MultiReportVisitor(visitors);
            visitor.visitInfo(execLoader.getSessionInfoStore().getInfos(), execLoader.getExecutionDataStore()
                    .getContents());
            final MultiSourceFileLocator sources = new MultiSourceFileLocator(2);
            for (final String s : srcDirName.split(",")) {
                sources.add(new DirectorySourceFileLocator(new File(s), "UTF-8", 2));
            }

            visitor.visitBundle(bundle, sources);
            visitor.visitEnd();
        }
    }

    private static void generateBrazilCoverage(final File xmlReport, final File resultDir) throws Exception {
        // Yes, we're parsing XML with a regex. I can't get XPATH to work
        final Pattern summaryPattern = Pattern.compile("</package>(.*)</report>", Pattern.DOTALL);
        final Pattern counterPattern = Pattern
                .compile("<counter\\s+type=\"([^\"]+)\"\\s+missed=\"(\\d+)\"\\s+covered=\"(\\d+)\"/>");

        final String xml = new String(Files.readAllBytes(xmlReport.toPath()), StandardCharsets.UTF_8);
        final Matcher summaryMatcher = summaryPattern.matcher(xml);
        summaryMatcher.find();
        final String summary = summaryMatcher.group(1);

        double line = 0;
        double branch = 0;

        final Matcher counterMatcher = counterPattern.matcher(summary);
        while (counterMatcher.find()) {
            final double missed = Double.parseDouble(counterMatcher.group(2));
            final double covered = Double.parseDouble(counterMatcher.group(3));
            final double result = (covered / (missed + covered)) * 100.0;
            switch (counterMatcher.group(1)) {
                case "LINE":
                    line = result;
                    break;
                case "BRANCH":
                    branch = result;
                    break;
            // Purposefully ignoring rest
            }
        }

        System.out.println("Java line coverage:   " + line + "%");
        System.out.println("Java branch coverage: " + branch + "%");

        final File outputFile = new File(resultDir, "coverage-data.txt");
        final Writer writer = new FileWriter(outputFile, true);
        writer.write("java:line:" + line + "\n");
        writer.write("java:branch:" + branch + "\n");
        writer.close();
    }

    private static List<File> findFiles(final File current, final String suffix) throws IOException {
        final List<File> result = new ArrayList<File>();
        for (final File f : current.listFiles()) {
            if (f.isDirectory()) {
                result.addAll(findFiles(f, suffix));
            } else if (f.isFile() && f.getName().endsWith(suffix)) {
                result.add(f);
            }
        }
        return result;
    }

}
