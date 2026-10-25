use super::*;

const T0: i64 = 1_792_000_020_000; // 20 s into a minute
const GB: u64 = 1024 * 1024 * 1024;

fn point(t: i64, cpu: Option<f64>) -> MetricPoint {
    MetricPoint {
        t,
        cpu_pct: cpu,
        mem_bytes: Some(2 * GB),
        mem_total_bytes: Some(4 * GB),
        swap_used_bytes: None,
        swap_total_bytes: None,
        disk_read_bps: Some(1000.4),
        disk_write_bps: None,
        net_rx_bps: None,
        net_tx_bps: None,
        load1: None,
        disk_used_pct: None,
    }
}

fn minute_of(t: i64) -> i64 {
    t.div_euclid(MINUTE_MS)
}

#[test]
fn a_minute_keeps_the_average_lowest_and_highest_of_its_rounds() {
    let mut rollup = Rollup::default();
    let key = r"C:\VMs\web\web.vmx";
    for (i, cpu) in [Some(10.0), Some(30.0), None, Some(f64::NAN), Some(20.0)]
        .into_iter()
        .enumerate()
    {
        let mut p = point(T0 + 5_000 * i64::try_from(i).unwrap(), cpu);
        p.mem_bytes = Some(GB * u64::try_from(i + 1).unwrap());
        p.disk_used_pct = Some(40.0 + f64::from(u32::try_from(i).unwrap()));
        rollup.add(HistorySource::Host, key, &p);
    }
    assert!(rollup.take_before(minute_of(T0)).is_empty(), "the minute is still open");
    let rows = rollup.take_before(minute_of(T0) + 1);
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(row.minute, minute_of(T0));
    assert_eq!(row.key, key);
    assert_eq!(row.samples, 5, "every round counts");
    assert_eq!(
        row.cpu_avg,
        Some(20.0),
        "readings that are missing or not a number are left out"
    );
    assert_eq!(row.cpu_min, Some(10.0));
    assert_eq!(row.cpu_max, Some(30.0));
    assert_eq!(row.mem_avg, Some(3 * GB));
    assert_eq!(row.mem_max, Some(5 * GB));
    assert_eq!(row.mem_total, Some(4 * GB), "the latest of what there is");
    assert_eq!(row.read_avg, Some(1000), "bytes per second as whole numbers");
    assert_eq!(row.write_avg, None);
    assert_eq!(row.disk_used_max, Some(44.0), "the fullest disk's highest reading");
    assert!(rollup.is_empty());
}

#[test]
fn only_finished_minutes_are_taken_until_the_app_closes() {
    let mut rollup = Rollup::default();
    let web = "web";
    let db = "db";
    rollup.add(HistorySource::Host, web, &point(T0, Some(1.0)));
    rollup.add(HistorySource::Guest, db, &point(T0 + 1_000, Some(2.0)));
    rollup.add(HistorySource::Host, web, &point(T0 + MINUTE_MS, Some(3.0)));
    rollup.add(
        HistorySource::ThisPc,
        THIS_PC_KEY,
        &point(T0 + 2 * MINUTE_MS, Some(4.0)),
    );
    let rows = rollup.take_before(minute_of(T0) + 1);
    let keys: Vec<(i64, HistorySource, String)> = rows.iter().map(|r| (r.minute, r.source, r.key.clone())).collect();
    assert_eq!(
        keys,
        [
            (minute_of(T0), HistorySource::Host, web.to_owned()),
            (minute_of(T0), HistorySource::Guest, db.to_owned()),
        ]
    );
    assert_eq!(rollup.first_minute(), Some(minute_of(T0) + 1));
    let rest = rollup.take_all();
    assert_eq!(rest.len(), 2, "the open minute too, when closing");
    assert_eq!(rest[1].source, HistorySource::ThisPc);
    assert!(rollup.is_empty());
}

fn row(minute: i64, samples: u32, cpu: Option<f64>, mem: Option<u64>) -> MinuteRow {
    MinuteRow {
        source: HistorySource::Guest,
        key: "s".into(),
        minute,
        samples,
        cpu_avg: cpu,
        cpu_min: cpu.map(|c| c - 5.0),
        cpu_max: cpu.map(|c| c + 5.0),
        mem_avg: mem,
        mem_max: mem,
        mem_total: Some(8 * GB),
        swap_avg: None,
        swap_total: Some(GB),
        read_avg: Some(100),
        write_avg: None,
        rx_avg: Some(10),
        tx_avg: Some(20),
        load_avg: Some(1.0),
        load_max: Some(2.0),
        disk_used_max: Some(50.0),
    }
}

#[test]
fn buckets_weigh_each_minute_by_its_rounds() {
    let base = 29_000_000; // a multiple of 5 and of 30
    let rows = [
        row(base, 12, Some(10.0), Some(GB)),
        row(base + 1, 4, Some(50.0), Some(3 * GB)),
        // A guest polled every 30 s has two rounds a minute; a minute with no CPU reading adds no weight.
        row(base + 2, 2, None, None),
        // The next bucket, after a gap of two minutes with nothing.
        row(base + 7, 6, Some(70.0), Some(2 * GB)),
    ];
    let points = bucket(&rows, 5);
    assert_eq!(points.len(), 2, "no point for a bucket with no minute");
    let first = points[0];
    assert_eq!(first.t, base * MINUTE_MS);
    assert_eq!(first.samples, 18);
    assert_eq!(first.cpu_pct, Some(20.0), "(10 * 12 + 50 * 4) / 16");
    assert_eq!(first.cpu_min, Some(5.0));
    assert_eq!(first.cpu_max, Some(55.0));
    assert_eq!(first.mem_bytes, Some(GB + GB / 2), "(1 * 12 + 3 * 4) / 16 GB");
    assert_eq!(first.mem_max_bytes, Some(3 * GB));
    assert_eq!(first.mem_total_bytes, Some(8 * GB));
    assert_eq!(first.swap_used_bytes, None);
    assert_eq!(first.swap_total_bytes, Some(GB));
    assert_eq!(first.disk_read_bps, Some(100.0));
    assert_eq!(first.net_tx_bps, Some(20.0));
    assert_eq!(first.load_max, Some(2.0));
    assert_eq!(first.disk_used_pct, Some(50.0));
    assert_eq!(points[1].t, (base + 5) * MINUTE_MS, "buckets start on whole multiples");
    assert_eq!(points[1].cpu_pct, Some(70.0));

    // One-minute buckets give the minutes back as they are.
    let minutes = bucket(&rows, 1);
    assert_eq!(minutes.len(), 4);
    assert_eq!(minutes[1].cpu_pct, Some(50.0));
    assert_eq!(minutes[2].cpu_pct, None);
    assert!(bucket(&[], 30).is_empty());
}

#[test]
fn ranges_have_a_few_hundred_points_at_most() {
    for (range, json, span, size) in [
        (HistoryRange::Hour, "\"1h\"", 60, 1),
        (HistoryRange::SixHours, "\"6h\"", 360, 1),
        (HistoryRange::Day, "\"24h\"", 1440, 5),
        (HistoryRange::Week, "\"7d\"", 10_080, 30),
    ] {
        assert_eq!(range.span_minutes(), span);
        assert_eq!(range.bucket_minutes(), size);
        assert!(span / size <= 360, "{json}: {} points", span / size);
        assert_eq!(serde_json::to_string(&range).unwrap(), json);
        assert_eq!(serde_json::from_str::<HistoryRange>(json).unwrap(), range);
    }
}

#[test]
fn the_history_is_kept_7_days_by_default() {
    assert_eq!(HistoryRetention::default(), HistoryRetention::Days7);
    let days: Vec<i64> = HistoryRetention::ALL.iter().map(|r| r.days()).collect();
    assert_eq!(days, [1, 3, 7, 14, 30]);
    for r in HistoryRetention::ALL {
        let json = serde_json::to_string(&r).unwrap();
        assert_eq!(serde_json::from_str::<HistoryRetention>(&json).unwrap(), r);
    }
    assert_eq!(serde_json::to_string(&HistoryRetention::Days7).unwrap(), "\"days7\"");
    for source in [HistorySource::Host, HistorySource::Guest, HistorySource::ThisPc] {
        assert_eq!(HistorySource::parse(source.as_str()), Some(source));
    }
}

#[test]
fn a_prune_says_what_went() {
    let report = HistoryPruneReport {
        at: "2026-10-25T08:00:00Z".into(),
        retention: HistoryRetention::Days7,
        before: "2026-10-18T08:00:00Z".into(),
        removed: HistoryPruned {
            minutes: 100_800,
            series: 1,
            alerts: 3,
        },
        compacted: true,
    };
    assert_eq!(
        describe(&report),
        "older than 7 days (before 2026-10-18): removed 100800 one-minute readings and 3 resolved alerts; \
         1 series that no longer report went with them; the database file was compacted"
    );
    assert_eq!(
        describe_size(&HistorySize {
            series: 3,
            minutes: 4320,
            oldest: None,
            bytes: Some(1_200_000),
        }),
        "1.2 MB for 3 series"
    );
}
