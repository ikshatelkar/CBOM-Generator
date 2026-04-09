package detection_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cbom-scanner/pkg/detection"
	"github.com/cbom-scanner/pkg/rules/java"
)

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

func newJavaEngine(t *testing.T) *detection.Engine {
	t.Helper()
	reg := detection.NewRuleRegistry()
	java.RegisterJCADetectionRules(reg)
	return detection.NewEngine(reg)
}

func writeTempFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("writeTempFile: %v", err)
	}
	return path
}

// --------------------------------------------------------------------------
// Source code fixtures
// --------------------------------------------------------------------------

const javaWithMD5 = `
import java.security.MessageDigest;
public class Foo {
    void hash() {
        MessageDigest md = MessageDigest.getInstance("MD5");
    }
}
`

const javaWithAES = `
import javax.crypto.Cipher;
public class Bar {
    void encrypt() {
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
    }
}
`

const javaClean = `
public class Clean {
    void doSomething() {
        System.out.println("hello world");
    }
}
`

// --------------------------------------------------------------------------
// ScanFile tests
// --------------------------------------------------------------------------

func TestScanFile_DetectsMD5(t *testing.T) {
	dir := t.TempDir()
	path := writeTempFile(t, dir, "Foo.java", javaWithMD5)

	engine := newJavaEngine(t)
	findings, err := engine.ScanFile(path, detection.LangJava)
	if err != nil {
		t.Fatalf("ScanFile error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding for MD5 usage")
	}

	found := false
	for _, f := range findings {
		for _, node := range f.Nodes {
			if strings.EqualFold(node.AsString(), "MD5") {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected an MD5 node in findings")
	}
}

func TestScanFile_DetectsAES(t *testing.T) {
	dir := t.TempDir()
	path := writeTempFile(t, dir, "Bar.java", javaWithAES)

	engine := newJavaEngine(t)
	findings, err := engine.ScanFile(path, detection.LangJava)
	if err != nil {
		t.Fatalf("ScanFile error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding for AES usage")
	}
}

func TestScanFile_NoFindingsForCleanFile(t *testing.T) {
	dir := t.TempDir()
	path := writeTempFile(t, dir, "Clean.java", javaClean)

	engine := newJavaEngine(t)
	findings, err := engine.ScanFile(path, detection.LangJava)
	if err != nil {
		t.Fatalf("ScanFile error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected zero findings for clean file, got %d", len(findings))
	}
}

func TestScanFile_UnknownLanguage_ReturnsNoFindings(t *testing.T) {
	dir := t.TempDir()
	path := writeTempFile(t, dir, "script.rb", `digest = OpenSSL::Digest::MD5.new`)

	engine := newJavaEngine(t)
	findings, err := engine.ScanFile(path, "ruby")
	if err != nil {
		t.Fatalf("ScanFile error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings for unregistered language, got %d", len(findings))
	}
}

func TestScanFile_NonexistentFile_ReturnsError(t *testing.T) {
	engine := newJavaEngine(t)
	_, err := engine.ScanFile("/nonexistent/path/Crypto.java", detection.LangJava)
	if err == nil {
		t.Error("expected error for nonexistent file, got nil")
	}
}

// --------------------------------------------------------------------------
// ScanDirectory tests
// --------------------------------------------------------------------------

func TestScanDirectory_FindsFileInSubdirectory(t *testing.T) {
	dir := t.TempDir()
	subdir := filepath.Join(dir, "src", "main", "java")
	if err := os.MkdirAll(subdir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	writeTempFile(t, subdir, "Crypto.java", javaWithMD5)

	engine := newJavaEngine(t)
	result := engine.ScanDirectory(dir)

	if len(result.Findings) == 0 {
		t.Error("expected findings from recursive directory scan")
	}
}

func TestScanDirectory_IgnoresNonSourceFiles(t *testing.T) {
	dir := t.TempDir()
	writeTempFile(t, dir, "README.md", `Use MessageDigest.getInstance("MD5")`)
	writeTempFile(t, dir, "config.xml", `<algorithm>MD5</algorithm>`)

	engine := newJavaEngine(t)
	result := engine.ScanDirectory(dir)

	if len(result.Findings) != 0 {
		t.Errorf("expected no findings for non-source files, got %d", len(result.Findings))
	}
}

func TestScanDirectory_SkipsGitDirectory(t *testing.T) {
	dir := t.TempDir()
	gitDir := filepath.Join(dir, ".git")
	if err := os.MkdirAll(gitDir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	// Crypto file inside .git should be skipped entirely
	writeTempFile(t, gitDir, "Crypto.java", javaWithMD5)

	engine := newJavaEngine(t)
	result := engine.ScanDirectory(dir)

	if len(result.Findings) != 0 {
		t.Errorf("expected no findings — .git directory must be skipped, got %d", len(result.Findings))
	}
}

func TestScanDirectory_SkipsVendorDirectory(t *testing.T) {
	dir := t.TempDir()
	vendorDir := filepath.Join(dir, "vendor")
	if err := os.MkdirAll(vendorDir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	writeTempFile(t, vendorDir, "Crypto.java", javaWithMD5)

	engine := newJavaEngine(t)
	result := engine.ScanDirectory(dir)

	if len(result.Findings) != 0 {
		t.Errorf("expected no findings — vendor directory must be skipped, got %d", len(result.Findings))
	}
}

func TestScanDirectory_EmptyDirectory_ReturnsNoFindings(t *testing.T) {
	dir := t.TempDir()
	engine := newJavaEngine(t)
	result := engine.ScanDirectory(dir)

	if len(result.Findings) != 0 {
		t.Errorf("expected zero findings in empty directory, got %d", len(result.Findings))
	}
}

// TestScanDirectory_ConcurrentMatchesSequential verifies that the worker-pool
// scan produces the same finding count regardless of worker count.
func TestScanDirectory_ConcurrentMatchesSequential(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 8; i++ {
		writeTempFile(t, dir, fmt.Sprintf("File%d.java", i), javaWithMD5)
	}

	reg := detection.NewRuleRegistry()
	java.RegisterJCADetectionRules(reg)

	e1 := detection.NewEngine(reg)
	e1.Workers = 1

	e4 := detection.NewEngine(reg)
	e4.Workers = 4

	r1 := e1.ScanDirectory(dir)
	r4 := e4.ScanDirectory(dir)

	if len(r1.Findings) != len(r4.Findings) {
		t.Errorf("sequential found %d findings, parallel (4 workers) found %d — should be equal",
			len(r1.Findings), len(r4.Findings))
	}
}
