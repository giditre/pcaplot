import pathlib
import sys

import matplotlib.pyplot as plt
import pandas as pd
import scapy.all as scapy

# define name for processed data file, useful for caching processed data
# NOTE: if a file with this name is found, the pcap files will not be processed
data_file = pathlib.Path(__file__).parent.joinpath("tmp_df.csv")

if data_file.exists():
    # load data from existing file
    with open(str(data_file), newline="") as f:
        overall_df = pd.read_csv(f, index_col="time")
else:
    # load pcap file as packet lists
    pcap_flows: dict[str, scapy.PacketList] = {
        file_path.stem: scapy.rdpcap(str(file_path))
        for file_path in pathlib.Path(__file__)
        .parent.parent.joinpath("sample_pcap_files", "test01")
        .glob("*.pcap")
    }

    # check loaded packet lists
    print(pcap_flows, end="\n\n")

    # define list of tables (DataFrames)
    df_list: list[pd.DataFrame] = []

    for name, packet_list in pcap_flows.items():

        print(f"Process capture file {name}")

        # build table (DataFrame) with a row per packet
        # each row contains packet capture time and payload size
        pcap_df: pd.DataFrame = pd.DataFrame(
            [
                (
                    int(p.time),  # rounding (by truncation) to integer
                    len(p.getlayer(scapy.UDP).payload) * 8,  # in bits
                )
                for p in packet_list
                if p.haslayer(scapy.UDP)
            ],
            columns=["time", name],
        )

        # sort packets by time
        pcap_df.sort_values(by=["time"], inplace=True)

        # compute data rate by grouping rows by time, summing the sizes
        pcap_df = pcap_df.groupby(pcap_df["time"]).aggregate({"time": "first", name: sum})

        # normalize (choose appropriate method)
        # TODO only normalize if required
        pcap_df[name] = pcap_df[name].div(pcap_df[name].max())
        # pcap_df[name] = (pcap_df[name] - pcap_df[name].mean()) / pcap_df[name].std()
        # pcap_df[name] = (pcap_df[name] - pcap_df[name].min()) / (
        #     pcap_df[name].max() - pcap_df[name].min()
        # )

        # set time as index
        pcap_df.set_index("time", inplace=True)

        # check table for this pcap
        print(pcap_df, end="\n\n")

        # append table to list
        df_list.append(pcap_df)

    # sort tables by size so that the first one is the longest
    df_list.sort(key=lambda x: x.size, reverse=True)

    # join the tables starting from the longest one
    overall_df = df_list[0].copy().join(df_list[1:]).fillna(0)

    # check overall table
    print(overall_df, end="\n\n")

    # offset time to that of the first packet (minimum time)
    overall_df.index = overall_df.index - overall_df.index.min()

    # save DataFrame to file
    overall_df.to_csv(data_file)

# check table to be plotted
print(overall_df)

# define figure
fig, fig_ax = plt.subplots()

# plot lines
plot_ax = overall_df.plot.line(
    use_index=True, xlabel="Time [s]", ylabel="Data rate [normalized to 1]", legend=False
)

# adjust markers and line styles
markers = [".", "+", "x", "o", "v", "^", "<", ">", "8", "s", "p", "*", "h", "H", "D", "d", "P", "X"]
linestyles = ["-", "--", ":", "-.", "-", "--", "-.", ":", "-", "--", "-.", ":"]
for line, marker, linestyle in zip(plot_ax.get_lines(), markers, linestyles):
    line.set_marker(marker)
    line.set_linestyle(linestyle)

# show the legend
plot_ax.legend()

# save the figure as pdf
plt.savefig(str(pathlib.Path(__file__).parent.joinpath("tmp_plot.pdf")), bbox_inches="tight")

# TODO if __name__ == "__main__"
# TODO argparse: input and output file name(s), filters, payload to be considered
