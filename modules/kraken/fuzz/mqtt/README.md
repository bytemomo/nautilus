Minimization: 

```
$ afl-tmin \
    -i output/default/crashes/<CRASHDUMP_TO_MINIMIZE> \
    -o <NAME>.min \
    -- ./fuzz_mosquitto @@
```
