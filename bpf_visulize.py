from models.AggregateMapObject import PacketAggregate, PacketMapKey, PacketAggregateMap, visualizeAggregateMap
from Helpers.file_to_object import FileToObject
import tkinter as tk
 
def open_visulize_aggregate():
    aggregate_maps  = FileToObject.parse_aggregate_map()
    visualizeAggregateMap(aggregate_maps)

def open_visulize_global():
    global_map = FileToObject.parse_global_map()
    global_map.visualize()
    
root = tk.Tk()
root.title("Roi Blum Project")

button1 = tk.Button(root, text="View Aggregate Map", command=open_visulize_aggregate)
button1.pack(side=tk.LEFT)

button2 = tk.Button(root, text="View Global Map", command=open_visulize_global)
button2.pack(side=tk.RIGHT)

root.mainloop()