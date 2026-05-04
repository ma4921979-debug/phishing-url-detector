with tab3:
    st.subheader("Admin Panel")

    password = st.text_input("Enter Admin Password", type="password")

    if password != ADMIN_PASSWORD:
        st.warning("Admin access only.")
    else:
        st.success("Welcome Admin")

        all_df = load_all_history()

        if all_df.empty:
            st.info("No data yet.")
        else:
            total = len(all_df)
            phishing = len(all_df[all_df["label"] == "High Risk / Phishing"])
            safe = len(all_df[all_df["label"] == "Low Risk / Safe"])
            avg = round(all_df["risk_score"].mean(), 2)
            users = all_df["session_id"].nunique()

            col1, col2, col3, col4, col5 = st.columns(5)

            col1.metric("Total Checks", total)
            col2.metric("Users", users)
            col3.metric("High Risk", phishing)
            col4.metric("Safe URLs", safe)
            col5.metric("Average Risk", f"{avg}%")

            st.subheader("All Users Risk Distribution")
            st.bar_chart(all_df["label"].value_counts())

            st.subheader("All Checked URLs")
            st.dataframe(
                all_df[["id", "session_id", "url", "risk_score", "label", "reasons", "checked_at"]],
                use_container_width=True
            )

            excel_file = convert_df_to_excel(all_df)

            st.download_button(
                label="📥 Export All Data as Excel",
                data=excel_file,
                file_name="all_phishing_checks.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            )

            st.subheader("Delete URL Check")

            delete_id = st.number_input(
                "Enter record ID to delete:",
                min_value=1,
                step=1
            )

            if st.button("Delete Record"):
                delete_record(delete_id)
                st.success(f"Record ID {delete_id} deleted successfully.")
                st.rerun()