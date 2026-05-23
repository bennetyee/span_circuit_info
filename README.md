# span_circuit_info

This is a vibe-coded reimplementation of the Python code in the
repository https://github.com/bennetyee/SPAN-hacks in Rust, but with
some added features, such as exponential backoff retry logic.  The API
is designed to work with https://github.com/bennetyee/live_plotter to
display interesting charts.

Remote viewing of circuit power usage is possible by running
`span_circuit_info` on a home server to log into a file, and then the
when away from home run `live_plotter` to access the data using `ssh
HOME tail +0f FILE | live_plotter ...` to display the strip chart.

I run

```sh
span_circuit_info -a --abs -k instantPowerW --live 5 --timestamp >> span-data/all-circuits.log
```

with the labels saved via a single invocation of

```sh
span_circuit_info -a -k name -q > span-data/labels
```

so that when I'm away from home, I can do

```sh
ssh HOME tail +0f span-data/all-circuits.log | eval live_plotter --timestamp --labels `cat span-data/labels ` -v $(expr 60 \* 60 \* 24)
```

(I have a local copy of the `labels` file.)
