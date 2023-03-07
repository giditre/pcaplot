import pathlib

import matplotlib.pyplot as plt
import pandas as pd
import scapy.all as scapy

data_file = pathlib.Path(__file__).parent.joinpath("tmp_df.csv")

if data_file.exists():
    with open(str(data_file), newline="") as f:
        df = pd.read_csv(f, index_col="time")
else:

    # pcap_file_name_list = [""]

    # pcap_flow = scapy.PcapReader("../sample_pcap_files/R11_R21.pcap")
    # pcap_flow = list(pcap_flow)

    # pcap_flow = scapy.rdpcap("../sample_pcap_files/R11_R21.pcap")

    pcap_flows: dict[str, scapy.PacketList] = {
        file_path.stem: scapy.rdpcap(str(file_path))
        for file_path in pathlib.Path(__file__)
        .parent.parent.joinpath("sample_pcap_files")
        .glob("*.pcap")
    }

    print(pcap_flows)

    df: pd.DataFrame = pd.DataFrame(
        [
            (
                name,
                int(p.time),
                len(p.getlayer(scapy.UDP)),
            )
            for name, packet_list in pcap_flows.items()
            for p in packet_list
            if p.haslayer(scapy.UDP)
        ],
        columns=["name", "time", "size"],
    )
    # sort packets by time
    df.sort_values(by=["time"], inplace=True)
    # refer time to that of first packet
    df["time"] = df["time"] - df["time"].min()
    # set time as index
    df.set_index("time", inplace=True)
    # compute data rate by grouping rows by time, summing the sizes
    df = df.groupby(df.index).aggregate({"name": "first", "size": "sum"})
    # save DataFrame to file
    df.to_csv(data_file)

print(df)

fig, ax = plt.subplots()

df = df.groupby("name")["size"].plot.line(
    y="size", marker=".", use_index=True, xlabel="Time [s]", ylabel="Data rate [B/s]", legend=True
)
# print(df)

# df.plot(y="size")

plt.savefig(str(pathlib.Path(__file__).parent.joinpath("tmp_plot.pdf")), bbox_inches="tight")

# TODO if __name__ == "__main__"
# TODO argparse: input and output file name(s), payload layer to be considered