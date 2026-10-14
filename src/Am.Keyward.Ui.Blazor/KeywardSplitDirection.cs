namespace Am.Keyward.Ui.Blazor;

/// <summary>How a <see cref="KeywardSplitter"/> divides its container.</summary>
public enum KeywardSplitDirection
{
    /// <summary>Left and right pane; the handle changes the left pane's width.</summary>
    Columns,

    /// <summary>Top and bottom pane; the handle changes the top pane's height.</summary>
    Rows,
}
