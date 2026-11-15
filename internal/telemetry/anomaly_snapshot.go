package telemetry

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// anomalySnapshotSchemaVersion guards the on-disk format. A mismatch on load
// means the WindowSize or metric set may have changed underneath an old file,
// so the snapshot is discarded rather than best-effort interpreted.
const anomalySnapshotSchemaVersion = 1

// ErrAnomalySnapshotSchemaMismatch is returned (wrapped) by Load when the
// snapshot's schema_version differs from anomalySnapshotSchemaVersion. Callers
// can distinguish it from parse/read failures with errors.Is, though the
// intended handling of all three is the same: log and start cold.
var ErrAnomalySnapshotSchemaMismatch = errors.New("anomaly snapshot schema version mismatch")

// windowSnapshot is the persisted form of a single metricWindow. Only the raw
// ring buffer, its write position, and its fullness are stored; median/MAD are
// always recomputed from values on load so stale derived stats cannot exist.
type windowSnapshot struct {
	Pos    int       `json:"pos"`
	Filled bool      `json:"filled"`
	Values []float64 `json:"values"`
}

// anomalySnapshotFile is the top-level on-disk document.
type anomalySnapshotFile struct {
	SchemaVersion int                                  `json:"schema_version"`
	SavedAt       time.Time                            `json:"saved_at"`
	Caches        map[string]map[string]windowSnapshot `json:"caches"`
	// DataGaps is each cache's history of gaps between data changes (see
	// DataTracker), in ns. Absent from snapshots of RAVENs before it,
	// which load with no history.
	DataGaps map[string]windowSnapshot `json:"data_gaps,omitempty"`
}

// snapshot returns a copy of the window's raw ring buffer plus its position
// and fullness. The values slice is copied, so the returned snapshot does not
// alias the live buffer.
func (w *metricWindow) snapshot() windowSnapshot {
	w.mu.Lock()
	defer w.mu.Unlock()

	vals := make([]float64, len(w.values))
	copy(vals, w.values)
	return windowSnapshot{
		Pos:    w.pos,
		Filled: w.filled,
		Values: vals,
	}
}

// restore loads snap into the window. It is a no-op when snap holds a different
// number of values than the window's capacity — e.g. an older snapshot taken
// under a different WindowSize — so a size change discards the stale window
// rather than corrupting the ring buffer.
func (w *metricWindow) restore(snap windowSnapshot) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if len(snap.Values) != w.cap {
		return
	}
	copy(w.values, snap.Values)
	w.pos = snap.Pos
	w.filled = snap.Filled
}

// Save atomically writes the detector's windows to path: it marshals to a
// sibling ".tmp" file (mode 0o600) and renames it over the target. The
// directory is expected to already exist (see EnsureAnomalySnapshotDir).
func (d *Detector) Save(path string) error {
	d.mu.Lock()
	file := anomalySnapshotFile{
		SchemaVersion: anomalySnapshotSchemaVersion,
		SavedAt:       time.Now().UTC(),
		Caches:        make(map[string]map[string]windowSnapshot, len(d.windows)),
	}
	for cache, metrics := range d.windows {
		cacheSnap := make(map[string]windowSnapshot, len(metrics))
		for metric, w := range metrics {
			cacheSnap[metric] = w.snapshot()
		}
		file.Caches[cache] = cacheSnap
	}
	d.mu.Unlock()
	if gaps := d.data.gapSnapshots(); len(gaps) > 0 {
		file.DataGaps = gaps
	}

	data, err := json.MarshalIndent(&file, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal anomaly snapshot: %w", err)
	}

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write anomaly snapshot temp file: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		// The target is left untouched; drop the temp file so it does not linger.
		_ = os.Remove(tmp)
		return fmt.Errorf("rename anomaly snapshot into place: %w", err)
	}
	return nil
}

// Load reads a snapshot from path and restores it into the detector's windows.
//
// A missing file yields an os.IsNotExist-satisfying error (the raw os.ReadFile
// error, returned unwrapped so os.IsNotExist keeps working). A parse failure or
// a schema_version mismatch (see ErrAnomalySnapshotSchemaMismatch) yields an
// error too; in every error case the detector is left untouched, since state is
// only mutated after the file is fully read and validated.
func (d *Detector) Load(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		// Not wrapped: os.IsNotExist does not unwrap fmt.Errorf chains, and the
		// os.PathError already carries the path for context.
		return err
	}

	var file anomalySnapshotFile
	if err := json.Unmarshal(data, &file); err != nil {
		return fmt.Errorf("parse anomaly snapshot %q: %w", path, err)
	}
	if file.SchemaVersion != anomalySnapshotSchemaVersion {
		return fmt.Errorf("%w: got %d, want %d",
			ErrAnomalySnapshotSchemaMismatch, file.SchemaVersion, anomalySnapshotSchemaVersion)
	}

	d.data.restoreGaps(file.DataGaps)
	d.mu.Lock()
	defer d.mu.Unlock()
	for cache, metrics := range file.Caches {
		cacheWindows := d.windows[cache]
		if cacheWindows == nil {
			cacheWindows = make(map[string]*metricWindow, len(metrics))
			d.windows[cache] = cacheWindows
		}
		for metric, snap := range metrics {
			w := cacheWindows[metric]
			if w == nil {
				w = newMetricWindow(d.cfg.WindowSize)
				cacheWindows[metric] = w
			}
			w.restore(snap)
		}
	}
	return nil
}

// EnsureAnomalySnapshotDir creates the directory that will hold the snapshot at
// path, with mode 0o700.
func EnsureAnomalySnapshotDir(path string) error {
	return os.MkdirAll(filepath.Dir(path), 0o700)
}
